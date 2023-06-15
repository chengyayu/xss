package xss

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Json map[string]interface{}

type Defender struct {
	skipFields []string
	policy     *bluemonday.Policy
}

func DefaultDefender(options ...Option) *Defender {
	options = append(options, SetSkipFields("password"))
	return NewDefender(bluemonday.StrictPolicy(), options...)
}

func NewDefender(policy *bluemonday.Policy, options ...Option) *Defender {
	res := &Defender{policy: policy}
	for _, option := range options {
		option(res)
	}
	return res
}

func (p *Defender) RemoveXSS() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		p.removeXSS(ctx)
		return
	}
}

func (p *Defender) removeXSS(ctx *gin.Context) {
	err := p.XssRemove(ctx)
	if err != nil {
		ctx.Abort()
		return
	}
	ctx.Next()
}

func (p *Defender) XssRemove(c *gin.Context) error {
	// https://golang.org/pkg/net/http/#Request
	ReqMethod := c.Request.Method

	reqContentType := c.Request.Header.Get("Content-Type")
	reqContentLen := c.Request.Header.Get("Content-Length")
	rclen, _ := strconv.Atoi(reqContentLen)

	// https://golang.org/src/net/http/request.go

	switch ReqMethod {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if rclen > 1 && reqContentType == "application/json" {
			if err := p.HandleJson(c); err != nil {
				return err
			}
		} else if reqContentType == "application/x-www-form-urlencoded" {
			if err := p.HandleXFormEncoded(c); err != nil {
				return err
			}
		} else if strings.Contains(reqContentType, "multipart/form-data") {
			if err := p.HandleMultiPartFormData(c, reqContentType); err != nil {
				return err
			}
		}
	case http.MethodGet:
		if err := p.HandleGETRequest(c); err != nil {
			return err
		}
	default:
		return nil
	}
	return nil
}

func (p *Defender) HandleJson(c *gin.Context) error {
	jsonBod, err := decodeJson(c.Request.Body)
	if err != nil {
		return err
	}

	buff, err := p.jsonToStringMap(jsonBod)
	if err != nil {
		return err
	}

	c.Request.Body = ioutil.NopCloser(&buff)
	return nil
}

func (p *Defender) jsonToStringMap(jsonBod interface{}) (bytes.Buffer, error) {
	switch jbt := jsonBod.(type) {
	case map[string]interface{}:
		xmj := jsonBod.(map[string]interface{})
		buff := p.ConstructJson(xmj)
		return buff, nil
	case []interface{}:
		var multiRec bytes.Buffer
		multiRec.WriteByte('[')
		buff := bytes.Buffer{}
		for _, n := range jbt {
			xmj := n.(map[string]interface{})
			buff = p.ConstructJson(xmj)
			multiRec.WriteString(buff.String())
			multiRec.WriteByte(',')
		}
		multiRec.Truncate(multiRec.Len() - 1) // remove last ','
		multiRec.WriteByte(']')
		return multiRec, nil
	default:
		return bytes.Buffer{}, errors.New("Unknown Content Type Received")
	}
}

func (p *Defender) HandleXFormEncoded(c *gin.Context) error {
	if c.Request.Body == nil {
		return nil
	}

	// https://golang.org/src/net/http/httputil/dump.go
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(c.Request.Body); err != nil {
		return err
	}

	m, uerr := url.ParseQuery(buf.String())
	if uerr != nil {
		return uerr
	}

	var bq bytes.Buffer
	for k, v := range m {
		//fmt.Println(k, " => ", v)
		bq.WriteString(k)
		bq.WriteByte('=')

		// do fields to skip
		var fndFld bool = false
		for _, field := range p.skipFields {
			if k == field {
				bq.WriteString(url.QueryEscape(v[0]))
				fndFld = true
				break
			}
		}
		if !fndFld {
			bq.WriteString(url.QueryEscape(p.policy.Sanitize(v[0])))
		}
		bq.WriteByte('&')
	}

	if bq.Len() > 1 {
		bq.Truncate(bq.Len() - 1) // remove last '&'
		bodOut := bq.String()
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))
	} else {
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buf.String())))
	}

	return nil
}

func (p *Defender) HandleMultiPartFormData(c *gin.Context, reqContentType string) error {
	var ioreader io.Reader = c.Request.Body

	boundary := reqContentType[strings.Index(reqContentType, "boundary=")+9 : len(reqContentType)]

	reader := multipart.NewReader(ioreader, boundary)

	var multiPrtFrm bytes.Buffer
	// unknown, so make up some param limit - 100 max should be enough
	for i := 0; i < 100; i++ {
		part, err := reader.NextPart()
		if err != nil {
			//fmt.Println("didn't get a part")
			break
		}

		var buf bytes.Buffer
		n, err := io.Copy(&buf, part)
		if err != nil {
			//fmt.Println("error reading part: %v\nread so far: %q", err, buf.String())
			return err
		}
		// XXX needed?
		if n <= 0 {
			//fmt.Println("read %d bytes; expected >0", n)
			return errors.New("error recreating Multipart form Request")
		}
		// https://golang.org/src/mime/multipart/multipart_test.go line 230
		multiPrtFrm.WriteString(`--` + boundary + "\r\n")
		// dont sanitize file content
		if part.FileName() != "" {
			fn := part.FileName()
			mtype := part.Header.Get("Content-Type")
			multiPrtFrm.WriteString(`Content-Disposition: form-data; name="` + part.FormName() + "\"; ")
			multiPrtFrm.WriteString(`filename="` + fn + "\";\r\n")
			// default to application/octet-stream
			if mtype == "" {
				mtype = `application/octet-stream`
			}
			multiPrtFrm.WriteString(`Content-Type: ` + mtype + "\r\n\r\n")
			multiPrtFrm.WriteString(buf.String() + "\r\n")
		} else {
			multiPrtFrm.WriteString(`Content-Disposition: form-data; name="` + part.FormName() + "\";\r\n\r\n")
			p := bluemonday.StrictPolicy()
			if "password" == part.FormName() {
				multiPrtFrm.WriteString(buf.String() + "\r\n")
			} else {
				multiPrtFrm.WriteString(p.Sanitize(buf.String()) + "\r\n")
			}
		}
	}
	multiPrtFrm.WriteString("--" + boundary + "--\r\n")

	//fmt.Println("MultiPartForm Out %v", multiPrtFrm.String())

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(multiPrtFrm.String())))

	return nil
}

func (p *Defender) HandleGETRequest(c *gin.Context) error {
	queryParams := c.Request.URL.Query()
	var fieldToSkip = map[string]bool{}
	for _, fts := range p.skipFields {
		fieldToSkip[fts] = true
	}
	for key, items := range queryParams {
		if fieldToSkip[key] {
			continue
		}
		queryParams.Del(key)
		for _, item := range items {
			queryParams.Set(key, p.policy.Sanitize(item))
		}
	}
	c.Request.URL.RawQuery = queryParams.Encode()
	return nil
}

func (p *Defender) buildJsonApplyPolicy(interf interface{}, policy *bluemonday.Policy) bytes.Buffer {
	var buff bytes.Buffer
	switch v := interf.(type) {
	case map[string]interface{}:
		bf := p.ConstructJson(v)
		buff.WriteString(bf.String())
		buff.WriteByte(',')
	case []interface{}:
		bf := p.unravelSlice(v, policy)
		buff.WriteString(bf.String())
		buff.WriteByte(',')
	case json.Number:
		buff.WriteString(policy.Sanitize(fmt.Sprintf("%v", v)))
		buff.WriteByte(',')
	case string:
		buff.WriteString(fmt.Sprintf("%q", policy.Sanitize(v)))
		buff.WriteByte(',')
	case float64:
		buff.WriteString(policy.Sanitize(strconv.FormatFloat(v, 'g', 0, 64)))
		buff.WriteByte(',')
	default:
		if v == nil {
			buff.WriteString(fmt.Sprintf("%s", "null"))
			buff.WriteByte(',')
		} else {
			buff.WriteString(policy.Sanitize(fmt.Sprintf("%v", v)))
			buff.WriteByte(',')
		}
	}
	return buff
}

func (p *Defender) unravelSlice(ss []interface{}, policy *bluemonday.Policy) bytes.Buffer {
	var buff bytes.Buffer
	buff.WriteByte('[')
	for _, item := range ss {
		switch tp := item.(type) {
		case map[string]interface{}:
			bf := p.ConstructJson(tp)
			buff.WriteString(bf.String())
			buff.WriteByte(',')
		case string:
			buff.WriteString(fmt.Sprintf("%q", policy.Sanitize(tp)))
			buff.WriteByte(',')
		}
	}
	buff.Truncate(buff.Len() - 1) // remove last ','
	buff.WriteByte(']')
	return buff
}

func (p *Defender) ConstructJson(mp Json) bytes.Buffer {
	var buff bytes.Buffer
	buff.WriteByte('{')

	for k, v := range mp {
		buff.WriteByte('"')
		buff.WriteString(k)
		buff.WriteByte('"')
		buff.WriteByte(':')

		// do fields to skip
		var fndFld bool = false
		for _, fts := range p.skipFields {
			if string(k) == fts {
				//buff.WriteString(`"` + fmt.Sprintf("%s", v) + `",`)
				buff.WriteString(fmt.Sprintf("%q", v))
				buff.WriteByte(',')
				fndFld = true
				break
			}
		}
		if fndFld {
			continue
		}

		apndBuff := p.buildJsonApplyPolicy(v, p.policy)
		buff.WriteString(apndBuff.String())
	}
	buff.Truncate(buff.Len() - 1) // remove last ','
	buff.WriteByte('}')

	return buff
}

func decodeJson(content io.Reader) (interface{}, error) {
	var jsonBod interface{}
	d := json.NewDecoder(content)
	d.UseNumber()
	err := d.Decode(&jsonBod)
	if err != nil {
		return nil, errNotJson
	}
	return jsonBod, err
}

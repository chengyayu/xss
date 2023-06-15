package xss

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"strings"
)

type BodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w BodyWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (p *Defender) FilterXSS() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		w := &BodyWriter{
			body:           &bytes.Buffer{},
			ResponseWriter: ctx.Writer,
		}
		ctx.Writer = w

		ctx.Next()

		oldBody := w.body

		respContentTp := ctx.Writer.Header().Get("content-type")
		// 不处理非 json 响应体
		if !strings.Contains(respContentTp, "application/json") {
			w.ResponseWriter.WriteString(oldBody.String())
			w.body.Reset()
			return
		}

		newBody, err := p.BuildNewBody(oldBody)
		if err != nil {
			ctx.AbortWithError(500, errXSSFilter)
			return
		}

		w.ResponseWriter.WriteString(newBody.String())
		w.body.Reset()
	}
}

func (p *Defender) BuildNewBody(body *bytes.Buffer) (*bytes.Buffer, error) {
	jsonBod, err := decodeJson(body)
	if err != nil {
		return nil, err
	}

	buff, err := p.jsonToStringMap(jsonBod)
	if err != nil {
		return nil, err
	}

	return &buff, nil
}

var errNotJson = errors.New("response is not a valid json")
var errXSSFilter = errors.New("xss 处理失败")

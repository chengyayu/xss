package xss

import "github.com/microcosm-cc/bluemonday"

type Option func(defender *Defender)

func SetSkipFields(ss ...string) Option {
	return func(defender *Defender) {
		defender.skipFields = ss
	}
}

func SetPolicy(policy *bluemonday.Policy) Option {
	return func(defender *Defender) {
		defender.policy = policy
	}
}

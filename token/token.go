package token

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	header       map[string]interface{}
	method       jwt.SigningMethod
	tokPrefix    string
	tokPrefixLen int
}

func New(header map[string]interface{}, method jwt.SigningMethod) (*Token, error) {
	r := &Token{
		header: make(map[string]interface{}),
		method: method,
	}
	jt := jwt.New(method)
	for k, v := range header {
		jt.Header[k] = v
		r.header[k] = v
	}
	b, err := json.Marshal(jt.Header)
	if err != nil {
		return nil, err
	}
	r.tokPrefix = jwt.EncodeSegment(b) + "."
	r.tokPrefixLen = len(r.tokPrefix)
	return r, nil
}

func (et *Token) Gen(payload jwt.MapClaims, secret []byte) (string, error) {
	jt := jwt.NewWithClaims(et.method, payload)
	for k, v := range et.header {
		jt.Header[k] = v
	}
	orig, err := jt.SignedString(secret)
	if err != nil {
		return "", err
	}
	return orig[et.tokPrefixLen:], nil
}

func (et *Token) Verify(token string, secret []byte) (jwt.MapClaims, error) {
	full := et.tokPrefix + token
	jt, err := jwt.Parse(full, func(tok *jwt.Token) (interface{}, error) {
		tok.Method = et.method
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if c, ok := jt.Claims.(jwt.MapClaims); ok && jt.Valid {
		return c, nil
	}
	return nil, errors.New("no pass")
}

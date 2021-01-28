package token

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"testing"
)

func TestEasyToken(t *testing.T) {
	et, err := New(map[string]interface{}{"hello": "world"}, jwt.SigningMethodHS256)
	if err != nil {
		panic(err)
	}
	var secret = "123456"
	token, err := et.Gen(jwt.MapClaims{"id": 123, "name": "Bob"}, []byte(secret))
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
	payload, err := et.Verify(token, []byte(secret))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", payload)
	//
	payload, err = et.Verify(token, []byte("123"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", payload)
}

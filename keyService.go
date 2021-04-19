package steranko

import "github.com/dgrijalva/jwt-go"

type KeyService interface {
	NewJWTKey() (string, interface{})
	FindJWTKey(*jwt.Token) (interface{}, error)
}

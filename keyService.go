package steranko

import (
	"github.com/golang-jwt/jwt/v5"
)

type KeyService interface {
	NewJWTKey() (string, any)
	FindJWTKey(*jwt.Token) (any, error)
}

package steranko

import (
	"github.com/benpate/data"
	"github.com/golang-jwt/jwt/v5"
)

type testKeyService string

func (ks testKeyService) GetCurrentKey(session data.Session) (string, any, error) {
	return "k1", []byte(ks), nil
}

func (ks testKeyService) FindKey(session data.Session) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		return []byte(ks), nil
	}
}

func getTestKeyService() KeyService {
	return testKeyService("secret")
}

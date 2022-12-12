package steranko

import "github.com/golang-jwt/jwt/v4"

type testKeyService string

func (ks testKeyService) NewJWTKey() (string, any) {
	return "k1", []byte(ks)
}

func (ks testKeyService) FindJWTKey(token *jwt.Token) (any, error) {
	return []byte(ks), nil
}

func getTestKeyService() KeyService {
	return testKeyService("secret")
}

package steranko

import "github.com/golang-jwt/jwt"

type testKeyService string

func (ks testKeyService) NewJWTKey() (string, interface{}) {
	return "k1", []byte(ks)
}

func (ks testKeyService) FindJWTKey(token *jwt.Token) (interface{}, error) {
	return []byte(ks), nil
}

func getTestKeyService() KeyService {
	return testKeyService("secret")
}

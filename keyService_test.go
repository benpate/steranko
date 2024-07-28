package steranko

import "github.com/golang-jwt/jwt/v5"

type testKeyService string

func (ks testKeyService) GetCurrentKey() (string, any, error) {
	return "k1", []byte(ks), nil
}

func (ks testKeyService) FindKey(token *jwt.Token) (any, error) {
	return []byte(ks), nil
}

func getTestKeyService() KeyService {
	return testKeyService("secret")
}

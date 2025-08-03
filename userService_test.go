package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/exp"
	"github.com/golang-jwt/jwt/v5"
)

///////////////////////////////
// Test User Service
///////////////////////////////

type testUserService struct {
	collection data.Collection
}

func (t *testUserService) New() User {
	return &testUser{}
}

func (t *testUserService) Load(session data.Session, username string, user User) error {

	filter := exp.Equal("username", username)
	err := t.collection.Load(filter, user.(*testUser))

	return err
}

func (t *testUserService) Save(session data.Session, user User, comment string) error {
	return t.collection.Save(user.(data.Object), comment)
}

func (t *testUserService) Delete(session data.Session, user User, comment string) error {
	return t.collection.Delete(user.(data.Object), comment)
}

func (t *testUserService) RequestPasswordReset(session data.Session, user User) error {
	return nil
}

func (t *testUserService) NewClaims() jwt.MapClaims {
	return jwt.MapClaims{}
}

func (t *testUserService) Claims(user User) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{
		"username": user.GetUsername(),
	}

	return claims, nil
}

func (t *testUserService) Close() {

}

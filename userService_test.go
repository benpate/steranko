package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/exp"
	"github.com/dgrijalva/jwt-go"
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

func (t *testUserService) Load(username string, user User) error {

	filter := exp.Equal("username", username)
	err := t.collection.Load(filter, user.(*testUser))

	return err
}

func (t *testUserService) Save(user User, comment string) error {
	return t.collection.Save(user.(data.Object), comment)
}

func (t *testUserService) Delete(user User, comment string) error {
	return t.collection.Delete(user.(data.Object), comment)
}

func (t *testUserService) RequestPasswordReset(user User) error {
	return nil
}

func (t *testUserService) NewClaims() jwt.Claims {
	return jwt.MapClaims{}
}

func (t *testUserService) Close() {

}

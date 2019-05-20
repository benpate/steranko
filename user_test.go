package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/derp"
)

type testUserService struct {
	session data.Session
}

func (t *testUserService) New() *User {
	return &User{}
}

func (t *testUserService) Load(username string) (*User, *derp.Error) {

	filter := data.Expression{{"username", "=", username}}
	result := &User{}

	err := t.session.Load("User", filter, result)

	return result, err
}

func (t *testUserService) Save(user *User, comment string) *derp.Error {
	return t.session.Save("User", user, comment)
}

func (t *testUserService) Delete(user *User, comment string) *derp.Error {
	return t.session.Delete("User", user, comment)
}

func (t *testUserService) Close() {

}

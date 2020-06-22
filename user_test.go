package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/data/expression"
	"github.com/benpate/data/journal"
	"github.com/benpate/derp"
)

///////////////////////////

type testUser struct {
	UserID   string
	Username string
	Password string
	journal.Journal
}

func (tu testUser) ID() string {
	return tu.UserID
}

func (tu testUser) GetUsername() string {
	return tu.Username
}

func (tu testUser) GetPassword() string {
	return tu.Password
}

func (tu *testUser) SetUsername(username string) {
	tu.Username = username
}

func (tu *testUser) SetPassword(password string) {
	tu.Password = password
}

type testUserService struct {
	session data.Session
}

func (t *testUserService) New() User {
	return &testUser{
		UserID: "",
	}
}

func (t *testUserService) Load(username string) (User, *derp.Error) {

	filter := expression.New({"username", "=", username}}
	result := &testUser{}

	err := t.session.Load("User", filter, result)

	return result, err
}

func (t *testUserService) Save(user User, comment string) *derp.Error {

	record, err := t.Load(user.GetUsername())

	if err != nil {
		return derp.Wrap(err, "testUserService.Save", "Error loading by username", user, comment)
	}

	record.SetUsername(user.GetUsername())
	record.SetPassword(user.GetPassword())

	if object, ok := record.(data.Object); ok {
		return t.session.Save("User", object, comment)
	}

	return derp.New(derp.CodeInternalError, "testUserService.Save", "Invalid object.  Can't cast as data.Object")
}

func (t *testUserService) Delete(user User, comment string) *derp.Error {

	record, err := t.Load(user.GetUsername())

	if err != nil {
		return derp.Wrap(err, "testUserService.Delete", "Error loading by username", user, comment)
	}

	record.SetUsername(user.GetUsername())
	record.SetPassword(user.GetPassword())

	if object, ok := record.(data.Object); ok {
		return t.session.Delete("User", object, comment)
	}

	return derp.New(derp.CodeInternalError, "testUserService.Delete", "Invalid object.  Can't cast as data.Object")
}

func (t *testUserService) Close() {

}

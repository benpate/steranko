package steranko

import (
	"context"

	"github.com/benpate/data"
	"github.com/benpate/data/expression"
	"github.com/benpate/data/journal"
	"github.com/benpate/data/mockdb"
	"github.com/benpate/derp"
)

///////////////////////////

type testUser struct {
	Username        string `bson:"username"`
	Password        string `bson:"password"`
	journal.Journal `bson:"journal"`
}

func (tu testUser) ID() string {
	return tu.Username
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

func (tu *testUser) Claims() map[string]interface{} {
	return map[string]interface{}{
		"am-test-user": true,
	}
}

type testUserService struct {
	collection data.Collection
}

func (t *testUserService) New() User {
	return &testUser{}
}

func (t *testUserService) Load(username string) (User, *derp.Error) {

	filter := expression.Equal("username", username)
	result := &testUser{}
	err := t.collection.Load(filter, result)

	return result, err
}

func (t *testUserService) Save(user User, comment string) *derp.Error {
	return t.collection.Save(user.(data.Object), comment)
}

func (t *testUserService) Delete(user User, comment string) *derp.Error {
	return t.collection.Delete(user.(data.Object), comment)
}

func (t *testUserService) RequestPasswordReset(user User) *derp.Error {
	return nil
}

func (t *testUserService) Close() {

}

func testNewUserService() UserService {

	db := mockdb.New()

	session, _ := db.Session(context.TODO())
	collection := session.Collection("Users")

	return &testUserService{
		collection: collection,
	}
}

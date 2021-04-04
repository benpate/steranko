package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/data/journal"
	"github.com/benpate/exp"
)

///////////////////////////////
// Test User Model Object
///////////////////////////////

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

///////////////////////////////
// Test User Service
///////////////////////////////

type testUserService struct {
	collection data.Collection
}

func (t *testUserService) New() User {
	return &testUser{}
}

func (t *testUserService) Load(username string) (User, error) {

	filter := exp.Equal("username", username)
	result := &testUser{}
	err := t.collection.Load(filter, result)

	return result, err
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

func (t *testUserService) Close() {

}

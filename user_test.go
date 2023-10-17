package steranko

import (
	"github.com/benpate/data/journal"
	"github.com/golang-jwt/jwt/v5"
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

func (tu *testUser) Claims() jwt.Claims {
	return jwt.MapClaims{
		"am-test-user": true,
	}
}

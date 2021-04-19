package steranko

import (
	"context"

	"github.com/benpate/data"
	mockdb "github.com/benpate/data-mock"
	"github.com/benpate/schema"
)

func getTestSteranko() *Steranko {
	return New(getTestUserService(), getTestKeyService(), Config{
		Token:          "header:Authorization",
		PasswordSchema: schema.Unmarshal(`{"type":"string", "minLength":10, "maxLength":20}`),
	})
}

func getTestUserService() UserService {

	userService := testUserService{
		collection: getTestCollection(),
	}

	mike := userService.New()
	mike.SetUsername("michael@jackson.com")
	mike.SetPassword("hee-hee")
	userService.Save(mike, "Created")

	janet := userService.New()
	janet.SetUsername("janet@jackson.com")
	janet.SetPassword("nasty")
	userService.Save(janet, "Created")

	andy := userService.New()
	andy.SetUsername("andrew@jackson.com")
	andy.SetPassword("whitehouse")
	userService.Save(andy, "Created")

	return &userService
}

func getTestCollection() data.Collection {

	db := mockdb.New()

	session, _ := db.Session(context.TODO())
	collection := session.Collection("Users")

	return collection
}

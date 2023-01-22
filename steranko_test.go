package steranko

import (
	"context"
	"encoding/json"

	"github.com/benpate/data"
	mockdb "github.com/benpate/data-mock"
	"github.com/benpate/rosetta/schema"
)

func getTestSteranko() *Steranko {

	var result schema.Schema

	json.Unmarshal([]byte(`{"type":"string", "minLength":10, "maxLength":20}`), &result)

	return New(getTestUserService(), getTestKeyService(), Config{
		Token:          "header:Authorization",
		PasswordSchema: result,
	})
}

func getTestUserService() UserService {

	userService := &testUserService{
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

	return userService
}

func getTestCollection() data.Collection {

	db := mockdb.New()

	session, _ := db.Session(context.TODO())
	collection := session.Collection("Users")

	return collection
}

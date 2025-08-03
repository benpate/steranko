package steranko

import (
	"context"
	"encoding/json"

	"github.com/benpate/data"
	mockdb "github.com/benpate/data-mock"
	"github.com/benpate/rosetta/schema"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/golang-jwt/jwt/v5"
)

func getTestSteranko() *Steranko[jwt.MapClaims] {

	var result schema.Schema

	if err := json.Unmarshal([]byte(`{"type":"string", "minLength":10, "maxLength":20}`), &result); err != nil {
		panic(err)
	}

	return New(
		getTestUserService(),
		getTestKeyService(),
		WithPasswordSchema[jwt.MapClaims](result),
		WithPasswordHasher[jwt.MapClaims](hash.Plaintext{}),
	)
}

func getTestUserService() UserService[jwt.MapClaims] {

	var session data.Session

	userService := &testUserService{
		collection: getTestCollection(),
	}

	mike := userService.New()
	mike.SetUsername("michael@jackson.com")
	mike.SetPassword("hee-hee")
	if err := userService.Save(session, mike, "Created"); err != nil {
		panic(err)
	}

	janet := userService.New()
	janet.SetUsername("janet@jackson.com")
	janet.SetPassword("nasty")
	if err := userService.Save(session, janet, "Created"); err != nil {
		panic(err)
	}

	andy := userService.New()
	andy.SetUsername("andrew@jackson.com")
	andy.SetPassword("whitehouse")
	if err := userService.Save(session, andy, "Created"); err != nil {
		panic(err)
	}

	return userService
}

func getTestCollection() data.Collection {

	db := mockdb.New()

	session, _ := db.Session(context.TODO())
	collection := session.Collection("Users")

	return collection
}

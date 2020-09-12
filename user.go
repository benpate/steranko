package steranko

import (
	"github.com/benpate/derp"
)

// UserService wraps all of the functions that must be provided to Steranko by your application.
// This API matches the presto.Service API very closely, so it should be possible to wrap an
// existing presto service to serve Steranko, too.
type UserService interface {

	// New creates a newly initialized User that is ready to use
	New() User

	// Load retrieves a single User from the database
	Load(username string) (User, *derp.Error)

	// Save inserts/updates a single User in the database
	Save(user User, comment string) *derp.Error

	// Delete removes a single User from the database
	Delete(user User, comment string) *derp.Error

	RequestPasswordReset(user User) *derp.Error

	// Close cleans up any connections opened by the service.
	Close()
}

// User interface wraps all of the functions that Steranko needs to authorize a user of the system.
// This is done so that Steranko can be retrofitted on to your existing data objects.  Just implement
// this interface, and a CRUD service, and you're all set.
type User interface {
	GetUsername() string // Returns the username of the User
	GetPassword() string // Returns the password of the User

	SetUsername(username string)    // Sets the username of the User
	SetPassword(ciphertext string)  // Sets the password of the User
	Claims() map[string]interface{} // Returns all claims (permissions) that this user has.
}

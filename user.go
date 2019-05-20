package steranko

import "github.com/benpate/derp"

// UserService wraps all of the functions that must be provided to Steranko by your application.
// This API matches the presto.Service API very closely, so it should be possible to wrap an
// existing presto service to serve Steranko, too.
type UserService interface {

	// New creates a newly initialized User that is ready to use
	New() User

	// Load retrieves a single User from the database
	Load(username string) (User, *derp.Error)

	// Save inserts/updates a single User in the database
	Save(object User, comment string) *derp.Error

	// Delete removes a single User from the database
	Delete(object User, comment string) *derp.Error

	// Close cleans up any connections opened by the service.
	Close()
}

// User defines all of the data required for Steranko to authenticate and authorize a person in the system.
type User struct {
	Username string
	Password string
}

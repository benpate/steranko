package steranko

import "github.com/golang-jwt/jwt/v5"

// UserService wraps all of the functions that must be provided to Steranko by your application.
type UserService interface {

	// New creates a newly initialized User that is ready to use
	New() User

	// Load retrieves a single User from the database
	Load(username string, user User) error

	// LoadBySubject retrieves a single User by the value stored in the token's
	// standard "sub" claim. Steranko uses this to re-verify an existing session,
	// so the subject should be a stable identifier (such as a primary key) that
	// does not change when the user edits their username or email.
	LoadBySubject(subject string, user User) error

	// Save inserts/updates a single User in the database
	Save(user User, comment string) error

	// Delete removes a single User from the database
	Delete(user User, comment string) error

	// RequestPasswordReset handles the application-specific details of
	// delivering a password reset message to the user.
	RequestPasswordReset(user User) error

	// NewClaims generates an empty jwt.Claims object.
	NewClaims() jwt.Claims

	// Claims generates a jwt.Claims object for the given user.
	Claims(user User) (jwt.Claims, error)

	// Close cleans up any connections opened by the service.
	Close()
}

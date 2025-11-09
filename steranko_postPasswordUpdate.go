package steranko

import (
	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
)

// PostPasswordUpdate implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to update their passwords.
func (s *Steranko) PostPasswordUpdate(ctx echo.Context) error {

	const location = "steranko.PostPasswordUpdate"

	// Bind transaction information to the request body
	txn := UpdatePasswordTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, location, "Error binding transaction parameters")
	}

	// try to authenticate the user with their old password
	user := s.userService.New()

	if err := s.authenticate(txn.Username, txn.OldPassword, user); err != nil {
		return derp.Wrap(err, location, "Cannot authenticate user", txn.Username)
	}

	// Validate that the password meets all system criteria
	if err := s.ValidatePassword(txn.NewPassword); err != nil {
		return derp.Wrap(err, location, "Password does not meet requirements")
	}

	// try to update the user information with their new password
	user.SetPassword(txn.NewPassword)

	if err := s.userService.Save(user, "Steranko: User Requested Password Update"); err != nil {
		return derp.Wrap(err, location, "Unable to save user record", user)
	}

	// Silence means success.
	return nil
}

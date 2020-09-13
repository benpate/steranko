package steranko

import (
	"github.com/benpate/derp"
	"github.com/labstack/echo"
)

// PostPasswordUpdate implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to update their passwords.
func (s *Steranko) PostPasswordUpdate(ctx echo.Context) error {

	// Bind transaction information to the request body
	txn := UpdatePasswordTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, "steranko.PostPasswordUpdate", "Error binding transaction parameters").Report()
	}

	// try to authenticate the user with their old password
	user, err := s.Authenticate(txn.Username, txn.OldPassword)

	if err != nil {
		return derp.Wrap(err, "steranko.PostPasswordUpdate", "Cannot authenticate user", txn.Username).Report()
	}

	if err := s.ValidatePassword(txn.NewPassword); err != nil {
		return derp.Wrap(err, "steranko.PostPasswordUpdate", "Password does not meet requirements")
	}

	// try to update the user information with their new password
	user.SetPassword(txn.NewPassword)

	if err := s.UserService.Save(user, "Steranko: User Requested Password Update"); err != nil {
		return derp.Wrap(err, "steranko.PostPasswordUpdate", "Error saving user record", user).Report()
	}

	// Silence means success.
	return nil
}

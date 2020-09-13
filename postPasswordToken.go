package steranko

import (
	"github.com/benpate/derp"
	"github.com/labstack/echo"
)

// PostPasswordToken implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to tell the server that they
// forgot their password.  This should initiate some way for the system to
// send them a one time token to create a new password.
func (s *Steranko) PostPasswordToken(ctx echo.Context) error {

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error binding transaction parameters").Report()
	}

	user, err := s.UserService.Load(txn.Username)

	if err != nil {

		if err.NotFound() {
			return derp.New(CodeUnauthorized, "steranko.PostSigninTransaction", "Unauthorized")
		}

		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error loading User account", txn.Username)
	}

	return s.UserService.RequestPasswordReset(user)
}

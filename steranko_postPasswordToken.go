package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
)

// PostPasswordToken implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to tell the server that they
// forgot their password.  This should initiate some way for the system to
// send them a one time token to create a new password.
func (s *Steranko[T]) PostPasswordToken(ctx echo.Context, session data.Session) error {

	const location = "steranko.PostPasswordToken"

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, location, "Error binding transaction parameters")
	}

	user := s.userService.New()

	if err := s.userService.Load(session, txn.Username, user); err != nil {

		if derp.IsNotFound(err) {
			return derp.UnauthorizedError(location, "Unauthorized")
		}

		return derp.Wrap(err, location, "Error loading User account", txn.Username)
	}

	if err := s.userService.RequestPasswordReset(session, user); err != nil {
		return derp.Wrap(err, location, "Error sending reset invitation")
	}

	return nil
}

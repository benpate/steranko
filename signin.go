package steranko

import (
	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
)

// Signin implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function if
// you want to extend its functionality.  If the signin is successful
// it automatically sets the "Authorization" cookie in the user's browser.
func (s *Steranko) Signin(ctx echo.Context) error {

	var txn SigninTransaction

	if err := ctx.Bind(&txn); err != nil {
		return derp.New(500, "steranko.Signin", "Invalid Request. Please try again later.")
	}

	// try to authenticate the user
	user, err := s.Authenticate(txn.Username, txn.Password)

	if err != nil {
		return derp.New(derp.CodeForbiddenError, "steranko.Signin", "Invalid username/password.  Please try again.")
	}

	// Try to create a JWT token
	token, err := s.createJWT(user)

	if err != nil {
		return derp.New(derp.CodeInternalError, "steranko.Signin", "Internal error.  Please try again later.")
	}

	s.setJWT(ctx, token)

	return nil
}

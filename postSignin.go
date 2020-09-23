package steranko

import (
	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
)

// PostSignin implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) PostSignin(ctx echo.Context) error {

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Report(derp.Wrap(err, "steranko.PostSigninTransaction", "Error binding transaction parameters"))
	}

	// try to authenticate the user
	user, err := s.Authenticate(txn.Username, txn.Password)

	if err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error loading User account", txn.Username)
	}

	// Try to create a JWT token
	token, err := s.createJWT(user)

	if err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error creating JWT token")
	}

	// Set this token to the context
	s.setJWT(ctx, token)

	// Success
	return nil
}

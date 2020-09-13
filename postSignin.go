package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/labstack/echo"
)

// Signin implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) PostSignin(ctx echo.Context) error {

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error binding transaction parameters").Report()
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

// PostUpdatePassword implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to update their passwords.
func (s *Steranko) PostUpdatePassword(ctx echo.Context) *derp.Error {

	// Bind transaction information to the request body
	txn := UpdatePasswordTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, "steranko.PostUpdatePassword", "Error binding transaction parameters").Report()
	}

	// try to authenticate the user with their old password
	user, err := s.Authenticate(txn.Username, txn.OldPassword)

	if err != nil {
		return derp.Wrap(err, "steranko.PostUpdatePassword", "Cannot authenticate user", txn.Username).Report()
	}

	// try to update the user information with their new password
	user.SetPassword(txn.NewPassword)

	if err := s.UserService.Save(user, "Steranko: User Requested Password Update"); err != nil {
		return derp.Wrap(err, "steranko.PostUpdatePassword", "Error saving user record", user).Report()
	}

	// Silence means success.
	return nil
}

// GetPasswordRules is an HandlerFunc that returns an array
// containing all of the password rule descriptions for this server.
func (s *Steranko) GetPasswordRules(ctx echo.Context) {

	result := []string{}

	for _, rule := range s.PasswordRules {

		if description := rule.PasswordRuleDescription("und"); description != "" {
			result = append(result, description)
		}
	}

	ctx.JSON(http.StatusOK, result)
}

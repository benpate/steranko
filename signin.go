package steranko

import (
	"net/http"

	"github.com/benpate/derp"
)

// GetPasswordRules is an HandlerFunc that returns an array
// containing all of the password rule descriptions for this server.
func (s *Steranko) GetPasswordRules(ctx Context) {

	result := []string{}

	for _, rule := range s.PasswordRules {

		if description := rule.PasswordRuleDescription("und"); description != "" {
			result = append(result, description)
		}
	}

	ctx.JSON(http.StatusOK, result)
}

// SigninTransaction includes all of the information that MUST be posted
// to Sterenko in order to sign in to the system.
type SigninTransaction struct {
	Username string
	Password string
}

// PostSigninTransaction implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) PostSigninTransaction(ctx Context) error {

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.New(derp.CodeBadRequestError, "steranko.PostSigninTransaction", "Error binding transaction parameters", err).Report()
	}

	user, err := s.UserService.Load(txn.Username)

	if err != nil {
		if err.NotFound() {
			ctx.NoContent(CodeUnauthorized)
		} else {
			return derp.Wrap(err, "steranko.PostSigninTransaction", "Error loading User account", txn.Username)
		}
	}

	// Fall through means that we have a matching user account.  Now, check the password

	ok, update := s.PasswordHasher.CompareHashedPassword(txn.Password, user.Password)

	if ok == false {
		return derp.New(CodeForbidden, "steranko.PostSigninTransaction", "Password does not match", txn.Username)
	}

	if update == true {

		if password, err := s.PasswordHasher.HashPassword(txn.Password); err == nil {
			user.Password = password
			s.UserService.Save(user, "Password automatically upgraded by Steranko")
		}
	}

	// Return Tokens??

	return nil
}

// PostForgotPassword implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to tell the server that they
// forgot their password.  This should initiate some way for the system to
// send them a one time token to create a new password.
func (s *Steranko) PostForgotPassword(ctx Context) {

}

// HandleUpdatePassword implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to update their passwords.
func (s *Steranko) HandleUpdatePassword(ctx Context) {

}

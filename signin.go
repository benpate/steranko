package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/list"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

// PostSigninTransaction implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) PostSigninTransaction(ctx echo.Context) *derp.Error {

	txn := SigninTransaction{}

	if err := ctx.Bind(&txn); err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error binding transaction parameters").Report()
	}

	// try to authenticate the user
	user, err := s.Authenticate(txn.Username, txn.Password)

	if err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error loading User account", txn.Username)
	}

	// Return Tokens??
	location, name := list.Split(s.Config.Token, ":")

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims(user.Claims())

	// Generate encoded token and send it as response.
	signedString, errr := token.SignedString([]byte("secret")) // TODO: this *MUST* come from a secure source.

	if errr != nil {
		return derp.Wrap(errr, "steranko.PostSigninTransaction", "Error Signing JWT Token")
	}

	if location == "cookie" {
		cookie := http.Cookie{
			Name:  name,
			Value: signedString,
		}
		ctx.SetCookie(&cookie)
	} else {
		ctx.Response().Header().Set(name, signedString)
	}

	return nil
}

// Authenticate verifies a username/password combination.
func (s *Steranko) Authenticate(username string, password string) (User, *derp.Error) {

	// Try to load the User from the UserService
	user, err := s.UserService.Load(username)

	if err != nil {

		if err.NotFound() {
			return nil, derp.New(CodeUnauthorized, "steranko.Authenticate", "Unauthorized", username)
		}

		return nil, derp.Wrap(err, "steranko.Authenticate", "Error loading User account", username)
	}

	// Fall through means that we have a matching user account.

	// Try to authenticate the password
	ok, update := s.PasswordHasher.CompareHashedPassword(password, user.GetPassword())

	if ok == false {
		return nil, derp.New(CodeUnauthorized, "steranko.Authenticate", "Unauthorized", username)
	}

	if update == true {

		if hashedValue, err := s.PasswordHasher.HashPassword(password); err == nil {
			user.SetPassword(hashedValue)
			_ = s.UserService.Save(user, "Password automatically upgraded by Steranko")
			// Intentionally ignoring errors updating the password because the user has already
			// authenticated.  If we can't update it now (for some reason) then we'll get it again, soon.
		}
	}

	return user, nil
}

// RequestPasswordReset implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to tell the server that they
// forgot their password.  This should initiate some way for the system to
// send them a one time token to create a new password.
func (s *Steranko) RequestPasswordReset(ctx echo.Context) *derp.Error {

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

package steranko

import (
	"github.com/benpate/derp"
)

// PostSignin implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) Signin(txn SigninTransaction) SigninResponse {

	// try to authenticate the user
	user, err := s.Authenticate(txn.Username, txn.Password)

	if err != nil {
		return SigninResponse{
			Username:     txn.Username,
			ErrorMessage: "Invalid username/password. Please try again.",
			Error:        derp.Wrap(err, "steranko.PostSigninTransaction", "Error authenticating user"),
		}
	}

	// Try to create a JWT token
	token, err := s.createJWT(user)

	if err != nil {
		return SigninResponse{
			Username:     txn.Username,
			ErrorMessage: "Internal Error.  Please try again later.",
			Error:        derp.Wrap(err, "steranko.PostSigninTransaction", "Error generating JWT Token"),
		}
	}

	return SigninResponse{
		Username: txn.Username,
		JWT:      token,
	}
}

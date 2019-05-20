package steranko

import "net/http"

// GetPasswordRules is an HandlerFunc that returns an array
// containing all of the password rule descriptions for this server.
func (s *Steranko) GetPasswordRules(ctx Context) {

	result := []string{}

	for _, plugin := range s.Plugins {

		if plugin, ok := plugin.(PasswordValidatorPlugin); ok {

			if description := plugin.PasswordRuleDescription("und"); description != "" {
				result = append(result, description)
			}
		}
	}

	ctx.JSON(http.StatusOK, result)
}

// PostSigninForm implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) PostSigninForm(ctx Context) {

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

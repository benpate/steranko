package steranko

import "net/http"

// Handler functions for signing in to a user account.

// HandleUserSignin implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to sign in to their accounts.
func (s *Steranko) HandleUserSignin(r *http.Request, w *http.Response) {

}

// HandleForgotPassword implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to tell the server that they
// forgot their password.  This should initiate some way for the system to
// send them a one time token to create a new password.
func (s *Steranko) HandleForgotPassword(r *http.Request, w *http.Response) {

}

// HandleUpdatePassword implements the http.HandlerFunc signature, and should
// be wired in to your REST API to allow users to update their passwords.
func (s *Steranko) HandleUpdatePassword(r *http.Request, w *http.Response) {

}
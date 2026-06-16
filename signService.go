package steranko

import "net/http"

// SigninService wraps all of the functions that must be provided to Steranko by your application.
type SigninService interface {

	// SigninSuccess reports a successful signin to the database.
	// This method SHOULD reset the signin failure count for the user.
	SigninSuccess(request *http.Request, username string)

	// SigninFailure reports a failed signin to the database.
	// This method SHOULD increment the signin failure count for the user.
	SigninFailure(request *http.Request, username string)

	// IsSigninLocked returns TRUE if the user is currently locked out due to too many signin failures.
	IsSigninLocked(request *http.Request, username string) bool
}

// NilSigninService is an empty implementation of SigninService that does nothing.
// It can be used as a default or placeholder implementation when no actual signin service is needed.
type NilSigninService struct{}

// SigninSuccess does nothing.
func (s NilSigninService) SigninSuccess(request *http.Request, username string) {}

// SigninFailure does nothing.
func (s NilSigninService) SigninFailure(request *http.Request, username string) {}

// IsSigninLocked always reports that the account is not locked.
func (s NilSigninService) IsSigninLocked(request *http.Request, username string) bool {
	return false
}

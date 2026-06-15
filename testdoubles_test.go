package steranko

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// This file collects test doubles that are shared across several test files
// in the steranko package. Keeping them in one place avoids redeclaration
// collisions and keeps the individual test files focused on behavior.

// rejectAllRule is a PasswordRule that rejects every password. It is used to
// confirm that ValidatePassword consults the configured rules.
type rejectAllRule struct{}

func (rejectAllRule) ID() string { return "reject-all" }

func (rejectAllRule) PasswordRuleDescription(language string) string { return "nothing is allowed" }

func (rejectAllRule) ValidatePassword(password string) (bool, string) {
	return false, "rejected by rule"
}

// allowAllRule is a PasswordRule that accepts every password. It is used to
// confirm that a passing rule does not block an otherwise valid password.
type allowAllRule struct{}

func (allowAllRule) ID() string { return "allow-all" }

func (allowAllRule) PasswordRuleDescription(language string) string { return "everything is allowed" }

func (allowAllRule) ValidatePassword(password string) (bool, string) { return true, "" }

// spySigninService records the calls made to it, and can be configured to
// report that an account is locked. It lets the signin tests assert on the
// security-relevant bookkeeping (failure counts, lockout) without a database.
type spySigninService struct {
	locked    bool
	successes []string
	failures  []string
}

func (s *spySigninService) SigninSuccess(request *http.Request, username string) {
	s.successes = append(s.successes, username)
}

func (s *spySigninService) SigninFailure(request *http.Request, username string) {
	s.failures = append(s.failures, username)
}

func (s *spySigninService) IsSigninLocked(request *http.Request, username string) bool {
	return s.locked
}

// errorKeyService is a KeyService that always fails. It is used to exercise the
// error paths in CreateJWT and GetAuthorization.
type errorKeyService struct{}

func (errorKeyService) GetCurrentKey() (string, any, error) {
	return "", nil, errors.New("no key available")
}

func (errorKeyService) FindKey(token *jwt.Token) (any, error) {
	return nil, errors.New("no key available")
}

// resetErrorUserService wraps a UserService and forces RequestPasswordReset to
// fail, so the PostPasswordToken error path can be tested. All other methods
// delegate to the embedded service.
type resetErrorUserService struct {
	UserService
}

func (s resetErrorUserService) RequestPasswordReset(user User) error {
	return errors.New("unable to send reset")
}

// claimsErrorUserService wraps a UserService and forces Claims generation to
// fail, exercising the internal-error path in SigninUser.
type claimsErrorUserService struct {
	UserService
}

func (s claimsErrorUserService) Claims(user User) (jwt.Claims, error) {
	return nil, errors.New("cannot build claims")
}

// staticFactory is a Factory that always returns the same Steranko instance
// (or an error). It is used to test the multi-tenant Middleware.
type staticFactory struct {
	steranko *Steranko
	err      error
}

func (f staticFactory) Steranko(ctx echo.Context) (*Steranko, error) {
	return f.steranko, f.err
}

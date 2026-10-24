package steranko

import (
	"errors"
	"net/http"

	"github.com/benpate/derp"
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

func (rejectAllRule) PasswordRuleDescription() string { return "nothing is allowed" }

func (rejectAllRule) ValidatePassword(password string) (bool, string) {
	return false, "rejected by rule"
}

// allowAllRule is a PasswordRule that accepts every password. It is used to
// confirm that a passing rule does not block an otherwise valid password.
type allowAllRule struct{}

func (allowAllRule) ID() string { return "allow-all" }

func (allowAllRule) PasswordRuleDescription() string { return "everything is allowed" }

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

// memoryUserService is a UserService that keeps each account's hashed password in a map
// keyed by username. Methods it does not override panic on the nil embedded value.
type memoryUserService struct {
	UserService
	hashes map[string]string
}

// New returns an empty testUser.
func (s memoryUserService) New() User {
	return &testUser{}
}

// Load copies the named account into the User, or returns a NotFound error.
func (s memoryUserService) Load(username string, user User) error {

	hashedValue, exists := s.hashes[username]

	if !exists {
		return derp.NotFound("memoryUserService.Load", "User not found")
	}

	user.SetUsername(username)
	user.SetHashedPassword(hashedValue)
	return nil
}

// Save stores the User's hashed password under its username.
func (s memoryUserService) Save(user User, comment string) error {
	s.hashes[user.GetUsername()] = user.GetHashedPassword()
	return nil
}

// spyUserService wraps a UserService, counting the calls made to Load and Save, and can
// force either one to fail.
type spyUserService struct {
	UserService
	loadErr error
	saveErr error
	loads   int
	saves   int
}

// Load counts the call, then returns loadErr when it is set or delegates otherwise.
func (s *spyUserService) Load(username string, user User) error {

	s.loads++

	if s.loadErr != nil {
		return s.loadErr
	}

	return s.UserService.Load(username, user)
}

// Save counts the call, then returns saveErr when it is set or delegates otherwise.
func (s *spyUserService) Save(user User, comment string) error {

	s.saves++

	if s.saveErr != nil {
		return s.saveErr
	}

	return s.UserService.Save(user, comment)
}

// newAccountsSteranko returns a Steranko whose users are the given accounts (username to
// hashed password), along with the spy that records every Load and Save made against them.
func newAccountsSteranko(accounts map[string]string, hashers ...PasswordHasher) (*Steranko, *spyUserService) {
	spy := &spyUserService{UserService: memoryUserService{hashes: accounts}}
	return New(spy, getTestKeyService(), WithPasswordHasher(hashers...)), spy
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

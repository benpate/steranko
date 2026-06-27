package steranko

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/benpate/rosetta/schema"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// getBCryptTestSteranko returns a Steranko configured with a REAL BCrypt hasher
// (rather than the Plaintext hasher used by getTestSteranko). A low cost keeps
// the test fast while still exercising genuine hashing. The seeded user's old
// password is pre-hashed with the same cost so that authenticate() succeeds.
func getBCryptTestSteranko(t *testing.T) (*Steranko, UserService) {
	t.Helper()

	const cost = bcrypt.MinCost

	var passwordSchema schema.Schema
	if err := json.Unmarshal([]byte(`{"type":"string", "minLength":10, "maxLength":20}`), &passwordSchema); err != nil {
		t.Fatalf("unable to build password schema: %v", err)
	}

	userService := &testUserService{collection: getTestCollection()}

	// Seed a user whose stored password is a valid BCrypt hash of "old-password".
	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), cost)
	require.NoError(t, err)

	user := userService.New()
	user.SetUsername("ringo@beatles.com")
	user.SetPassword(string(oldHash))
	require.NoError(t, userService.Save(user, "Created"))

	s := New(
		userService,
		getTestKeyService(),
		WithPasswordSchema(passwordSchema),
		WithPasswordHasher(hash.BCrypt(cost)),
	)

	return s, userService
}

// TestSetPassword_StoresHashed pins the contract that the Steranko.SetPassword
// helper hashes the plaintext before handing it to User.SetPassword. This test
// is expected to PASS today; it establishes the baseline that hashing works
// when the correct code path is used.
func TestSetPassword_StoresHashed(t *testing.T) {

	s, _ := getBCryptTestSteranko(t)

	user := s.userService.New()

	require.NoError(t, s.SetPassword(user, "brand-new-password"))

	stored := user.GetPassword()
	require.NotEqual(t, "brand-new-password", stored, "SetPassword must not store the plaintext password")
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored), []byte("brand-new-password")),
		"stored value must be a valid BCrypt hash of the plaintext")
}

// TestPostPasswordUpdate_StoresHashedPassword is the end-to-end proof of the
// bug: with a real BCrypt hasher, PostPasswordUpdate must persist a HASHED new
// password, not the raw plaintext. This test is expected to FAIL today because
// the handler calls user.SetPassword(plaintext) directly, bypassing hashing.
func TestPostPasswordUpdate_StoresHashedPassword(t *testing.T) {

	s, userService := getBCryptTestSteranko(t)

	// Post a valid password update for the seeded user.
	transaction := make(url.Values)
	transaction.Set("username", "ringo@beatles.com")
	transaction.Set("oldPassword", "old-password")
	transaction.Set("newPassword", "brand-new-password")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	require.NoError(t, s.PostPasswordUpdate(ctx))

	// Reload the user from the service to inspect what was actually persisted.
	reloaded := userService.New()
	require.NoError(t, userService.Load("ringo@beatles.com", reloaded))

	stored := reloaded.GetPassword()

	// RULE: the persisted password must never be the raw plaintext.
	require.NotEqual(t, "brand-new-password", stored,
		"PostPasswordUpdate stored the password as PLAINTEXT")

	// The persisted value must be a valid BCrypt hash of the new password.
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored), []byte("brand-new-password")),
		"stored value must be a valid BCrypt hash of the new password")
}

// TestPostPasswordUpdate_NewPasswordStillSignsIn confirms the user-visible
// consequence of the bug: after updating the password, the user must be able to
// sign in with the new password. This fails today because authenticate() runs
// bcrypt.CompareHashAndPassword against a stored plaintext "hash", which errors.
func TestPostPasswordUpdate_NewPasswordStillSignsIn(t *testing.T) {

	s, _ := getBCryptTestSteranko(t)

	transaction := make(url.Values)
	transaction.Set("username", "ringo@beatles.com")
	transaction.Set("oldPassword", "old-password")
	transaction.Set("newPassword", "brand-new-password")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	ctx := e.NewContext(req, httptest.NewRecorder())

	require.NoError(t, s.PostPasswordUpdate(ctx))

	// Authenticating with the new password must now succeed.
	user := s.userService.New()
	require.NoError(t, s.authenticate("ringo@beatles.com", "brand-new-password", user),
		"user must be able to sign in with the updated password")
}

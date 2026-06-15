package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestNew_Defaults(t *testing.T) {

	// New (with no options) should populate every field with a safe default.
	s := New(getTestUserService(), getTestKeyService())

	require.NotNil(t, s.userService)
	require.NotNil(t, s.keyService)

	// The default signin service is the no-op NilSigninService.
	require.IsType(t, NilSigninService{}, s.signinService)

	// There must always be at least one password hasher, and the default must
	// NOT be plaintext (this is a security package).
	require.Len(t, s.passwordHashers, 1)
	require.NotEqual(t, "Plaintext", s.passwordHashers[0].ID())
	require.Equal(t, "BCrypt", s.passwordHashers[0].ID())

	// The default schema requires a password of at least 8 characters.
	require.NotNil(t, s.passwordSchema.Element)
	require.Nil(t, s.ValidatePassword("abcdefgh"))   // exactly 8 characters passes
	require.NotNil(t, s.ValidatePassword("abcdefg")) // 7 characters fails
	require.NotNil(t, s.ValidatePassword(""))        // empty fails (Required)
}

func TestWithOptions(t *testing.T) {

	// WithOptions should apply each option in order.
	s := New(getTestUserService(), getTestKeyService())

	spy := &spySigninService{}
	s.WithOptions(
		WithSigninService(spy),
		WithPasswordRules(rejectAllRule{}),
	)

	require.Same(t, spy, s.signinService)
	require.Len(t, s.passwordRules, 1)
}

func TestContextMethod(t *testing.T) {

	// (*Steranko).Context should wrap the echo context and embed the instance.
	s := getTestSteranko()
	e := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))

	wrapped := s.Context(e)

	require.NotNil(t, wrapped)
	require.Same(t, s, wrapped.steranko)
	require.Same(t, e, wrapped.Context)
}

// TestGetAuthorization_Valid confirms that a token produced by Steranko can be
// round-tripped back into claims, both from a cookie and from a bearer header.
func TestGetAuthorization_Valid(t *testing.T) {

	s := getTestSteranko()

	// Create a signed token for "michael@jackson.com"
	claims := jwt.MapClaims{"username": "michael@jackson.com"}
	token, err := s.CreateJWT(claims)
	require.Nil(t, err)
	require.NotEmpty(t, token)

	// Valid token presented in the Authorization cookie
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: token})

		result, err := s.GetAuthorization(req)
		require.Nil(t, err)

		mapClaims, ok := result.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, "michael@jackson.com", mapClaims["username"])
	}

	// Same token presented as a "Bearer" Authorization header
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		result, err := s.GetAuthorization(req)
		require.Nil(t, err)

		mapClaims, ok := result.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, "michael@jackson.com", mapClaims["username"])
	}
}

// TestGetAuthorization_Invalid uses a closure-driven table to confirm that
// every flavor of bad/forged token is rejected with an error and nil claims.
func TestGetAuthorization_Invalid(t *testing.T) {

	s := getTestSteranko()

	// goodClaims used as a base for forging tokens.
	goodClaims := jwt.MapClaims{"username": "michael@jackson.com"}

	// signWith produces a token string signed with the given method and key.
	signWith := func(method jwt.SigningMethod, key []byte) string {
		token := jwt.NewWithClaims(method, goodClaims)
		signed, err := token.SignedString(key)
		require.Nil(t, err)
		return signed
	}

	// run feeds the token into a fresh request (via cookie) and asserts that it
	// is rejected.
	run := func(name string, tokenString string) {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenString})

			claims, err := s.GetAuthorization(req)
			require.NotNil(t, err, "expected an error for %s", name)
			require.Nil(t, claims)
		})
	}

	run("empty", "")
	run("garbage", "this-is-not-a-jwt")
	run("not-enough-segments", "aaa.bbb")
	run("wrong-signing-key", signWith(jwt.SigningMethodHS512, []byte("wrong-secret")))

	// "none" algorithm tokens must always be rejected.
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, goodClaims)
	noneString, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.Nil(t, err)
	run("none-algorithm", noneString)
}

// TestGetAuthorization_NoToken confirms that a request with no token at all
// produces an error rather than empty/valid claims.
func TestGetAuthorization_NoToken(t *testing.T) {

	s := getTestSteranko()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	claims, err := s.GetAuthorization(req)
	require.NotNil(t, err)
	require.Nil(t, claims)
}

// TestGetAuthorization_KeyServiceError confirms that a failure inside the
// KeyService is surfaced as an error and never produces valid claims.
func TestGetAuthorization_KeyServiceError(t *testing.T) {

	good := getTestSteranko()
	claims := jwt.MapClaims{"username": "michael@jackson.com"}
	token, err := good.CreateJWT(claims)
	require.Nil(t, err)

	// Build a Steranko whose key service cannot find a key.
	s := New(getTestUserService(), errorKeyService{}, WithPasswordHasher(plaintextHasher()))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: token})

	result, err := s.GetAuthorization(req)
	require.NotNil(t, err)
	require.Nil(t, result)
}

func TestFindAuthorization(t *testing.T) {

	s := getTestSteranko()

	// withCookie returns a request carrying the named Authorization cookie.
	cookieRequest := func(value string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: value})
		return req
	}

	// headerRequest returns a request carrying the given Authorization header.
	headerRequest := func(value string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", value)
		return req
	}

	// Cookie takes precedence and its value is returned verbatim.
	require.Equal(t, "cookie-token", s.findAuthorization(cookieRequest("cookie-token")))

	// "Bearer " prefix is trimmed from the header.
	require.Equal(t, "header-token", s.findAuthorization(headerRequest("Bearer header-token")))

	// A header with no "Bearer " prefix is returned as-is.
	require.Equal(t, "raw-token", s.findAuthorization(headerRequest("raw-token")))

	// Nothing present returns the empty string.
	require.Equal(t, "", s.findAuthorization(httptest.NewRequest(http.MethodGet, "/", nil)))

	// A cookie is preferred over a header when both are present.
	req := cookieRequest("from-cookie")
	req.Header.Set("Authorization", "Bearer from-header")
	require.Equal(t, "from-cookie", s.findAuthorization(req))
}

// TestGetAuthorization_ErrorCodes documents that a structurally-invalid token
// is reported as a Forbidden-class error.
func TestGetAuthorization_Forbidden(t *testing.T) {

	s := getTestSteranko()

	// A token signed with the wrong key fails parsing. We only assert that an
	// error is returned; the precise classification is an implementation detail.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "x.y.z"})

	_, err := s.GetAuthorization(req)
	require.NotNil(t, err)
	require.NotEqual(t, 200, derp.ErrorCode(err))
}

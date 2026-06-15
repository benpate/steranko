package steranko

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// formRequest builds a POST request whose body carries the given form values.
func formRequest(values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	return req
}

func TestSigninFormPost_Success(t *testing.T) {

	spy := &spySigninService{}
	s := getTestSteranko()
	s.WithOptions(WithSigninService(spy))

	form := url.Values{}
	form.Set("username", "michael@jackson.com")
	form.Set("password", "hee-hee")

	ctx, rec := echoContextWithRecorder(t, formRequest(form))

	user, err := s.SigninFormPost(ctx)

	require.Nil(t, err)
	require.NotNil(t, user)
	require.Equal(t, "michael@jackson.com", user.GetUsername())

	// A successful signin must be recorded, and no failure logged.
	require.Equal(t, []string{"michael@jackson.com"}, spy.successes)
	require.Empty(t, spy.failures)

	// A signin cookie must have been written to the browser.
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)

	var authCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "Authorization" {
			authCookie = cookie
		}
	}
	require.NotNil(t, authCookie, "expected an Authorization cookie")
	require.NotEmpty(t, authCookie.Value)
	require.True(t, authCookie.HttpOnly, "signin cookie must be HttpOnly")
	require.Equal(t, http.SameSiteLaxMode, authCookie.SameSite)
	require.Equal(t, "/", authCookie.Path)
}

func TestSigninFormPost_BadPassword(t *testing.T) {

	spy := &spySigninService{}
	s := getTestSteranko()
	s.WithOptions(WithSigninService(spy))

	form := url.Values{}
	form.Set("username", "michael@jackson.com")
	form.Set("password", "wrong-password")

	ctx, rec := echoContextWithRecorder(t, formRequest(form))

	user, err := s.SigninFormPost(ctx)

	require.NotNil(t, err)
	require.Nil(t, user)
	require.True(t, derp.IsForbidden(err))

	// The failure must be recorded and no success logged.
	require.Equal(t, []string{"michael@jackson.com"}, spy.failures)
	require.Empty(t, spy.successes)

	// No signin cookie should be written for a failed signin.
	for _, cookie := range rec.Result().Cookies() {
		require.NotEqual(t, "Authorization", cookie.Name)
	}
}

func TestSigninFormPost_UnknownUser(t *testing.T) {

	spy := &spySigninService{}
	s := getTestSteranko()
	s.WithOptions(WithSigninService(spy))

	form := url.Values{}
	form.Set("username", "nobody@nowhere.com")
	form.Set("password", "whatever")

	ctx := echoContext(t, formRequest(form))

	user, err := s.SigninFormPost(ctx)

	require.NotNil(t, err)
	require.Nil(t, user)
	require.True(t, derp.IsForbidden(err))
	require.Equal(t, []string{"nobody@nowhere.com"}, spy.failures)
}

func TestSigninFormPost_LockedOut(t *testing.T) {

	spy := &spySigninService{locked: true}
	s := getTestSteranko()
	s.WithOptions(WithSigninService(spy))

	// Even with the CORRECT password, a locked account must be refused.
	form := url.Values{}
	form.Set("username", "michael@jackson.com")
	form.Set("password", "hee-hee")

	ctx := echoContext(t, formRequest(form))

	user, err := s.SigninFormPost(ctx)

	require.NotNil(t, err)
	require.Nil(t, user)
	require.True(t, derp.IsForbidden(err))

	// A lockout still records a failure, and never a success.
	require.Equal(t, []string{"michael@jackson.com"}, spy.failures)
	require.Empty(t, spy.successes)
}

func TestSigninFormPost_BadRequest(t *testing.T) {

	s := getTestSteranko()

	// A JSON content-type with a malformed body should fail to bind.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{not-valid-json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	ctx := echoContext(t, req)

	user, err := s.SigninFormPost(ctx)

	require.NotNil(t, err)
	require.Nil(t, user)
	require.True(t, derp.IsBadRequest(err))
}

func TestSigninUser(t *testing.T) {

	s := getTestSteranko()

	user := s.userService.New()
	user.SetUsername("michael@jackson.com")

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.SigninUser(ctx, user))

	// A valid Authorization cookie must be written, and its token must parse
	// back to the same user.
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)

	claims, err := s.GetAuthorization(cookieRequestFrom(cookies))
	require.Nil(t, err)
	require.Equal(t, "michael@jackson.com", claims.(jwt.MapClaims)["username"])
}

// TestSigninUser_ClaimsError confirms that a failure generating JWT claims is
// surfaced as an error and that no signin cookie is written.
func TestSigninUser_ClaimsError(t *testing.T) {

	s := getTestSteranko()
	s.userService = claimsErrorUserService{UserService: s.userService}

	user := s.userService.New()
	user.SetUsername("michael@jackson.com")

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	err := s.SigninUser(ctx, user)

	require.NotNil(t, err)
	require.Empty(t, rec.Result().Cookies(), "no cookie should be set when claims fail")
}

func TestSetCookie_NonTLS(t *testing.T) {

	s := getTestSteranko()
	claims := jwt.MapClaims{"username": "michael@jackson.com"}

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	require.Nil(t, s.SetCookie(ctx, claims))

	cookie := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, cookie)
	require.False(t, cookie.Secure, "non-TLS connection should not set a Secure cookie")
	require.True(t, cookie.HttpOnly)
	require.Equal(t, 2592000, cookie.MaxAge)
}

func TestSetCookie_TLS(t *testing.T) {

	s := getTestSteranko()
	claims := jwt.MapClaims{"username": "michael@jackson.com"}

	// httptest.NewRequest with an https target marks the request as TLS.
	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))

	require.Nil(t, s.SetCookie(ctx, claims))

	// On a secure connection the cookie name is locked to the host and Secure.
	cookie := findCookie(t, rec.Result().Cookies(), "__Host-Authorization")
	require.NotNil(t, cookie, "TLS connection must use the __Host- prefixed cookie")
	require.True(t, cookie.Secure, "TLS connection must set a Secure cookie")
	require.True(t, cookie.HttpOnly)
}

func TestCreateJWT(t *testing.T) {

	s := getTestSteranko()
	claims := jwt.MapClaims{"username": "michael@jackson.com"}

	token, err := s.CreateJWT(claims)

	require.Nil(t, err)
	require.NotEmpty(t, token)

	// The token must use the HS512 signing method and carry the key id header.
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.Nil(t, err)
	require.Equal(t, "HS512", parsed.Header["alg"])
	require.Equal(t, "k1", parsed.Header["kid"])
}

func TestCreateJWT_KeyServiceError(t *testing.T) {

	// A failure retrieving the signing key must surface as an error and
	// produce no usable token.
	s := New(getTestUserService(), errorKeyService{}, WithPasswordHasher(plaintextHasher()))

	token, err := s.CreateJWT(jwt.MapClaims{"username": "michael@jackson.com"})

	require.NotNil(t, err)
	require.Empty(t, token)
}

func TestValidatePassword_Rules(t *testing.T) {

	// A password that satisfies the schema but is rejected by a rule must fail.
	{
		s := getTestSteranko()
		s.WithOptions(WithPasswordRules(rejectAllRule{}))
		err := s.ValidatePassword("valid-password")
		require.NotNil(t, err)
		require.True(t, derp.IsBadRequest(err))
	}

	// A passing rule must not block an otherwise valid password.
	{
		s := getTestSteranko()
		s.WithOptions(WithPasswordRules(allowAllRule{}))
		require.Nil(t, s.ValidatePassword("valid-password"))
	}

	// The schema is still enforced even when a rule would pass.
	{
		s := getTestSteranko()
		s.WithOptions(WithPasswordRules(allowAllRule{}))
		require.NotNil(t, s.ValidatePassword("short")) // too short for the test schema (min 10)
	}
}

// cookieRequestFrom builds a GET request carrying the provided cookies.
func cookieRequestFrom(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req
}

// findCookie returns the named cookie from the slice, or nil if absent.
func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

package steranko

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// testRevalClaims is a claims type that opts in to revalidation by implementing
// Revalidatable. It carries a standard "sub" (via the embedded RegisteredClaims)
// and a "srev" revalidation timestamp. The "srev" field is JSON-tagged so it
// survives signing/parsing, mirroring how a real application's claims surface the
// data steranko needs.
type testRevalClaims struct {
	jwt.RegisteredClaims
	RevalidatedAt int64 `json:"srev,omitempty"`
}

func (c testRevalClaims) GetRevalidationTime() (time.Time, bool) {
	if c.RevalidatedAt == 0 {
		return time.Time{}, false
	}
	return time.Unix(c.RevalidatedAt, 0), true
}

// revalClaims builds opted-in claims with a "sub" and a revalidation time set the
// given duration in the past, so tests can place a session inside or outside the
// revalidation window at will.
func revalClaims(subject string, age time.Duration) testRevalClaims {
	return testRevalClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject},
		RevalidatedAt:    time.Now().Add(-age).Unix(),
	}
}

// revalUserService is a UserService whose claims implement Revalidatable, so the
// full middleware/parse path can be exercised end-to-end. It loads any subject
// successfully (returning a fresh opted-in claims set) unless wrapped to fail.
type revalUserService struct {
	UserService
}

func (revalUserService) NewClaims() jwt.Claims {
	return &testRevalClaims{}
}

func (revalUserService) Claims(user User) (jwt.Claims, error) {
	// A freshly built session is verified "now".
	return &testRevalClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: user.GetUsername()},
		RevalidatedAt:    time.Now().Unix(),
	}, nil
}

func (s revalUserService) LoadBySubject(subject string, user User) error {
	user.SetUsername(subject)
	return nil
}

// stalRevalToken mints a real signed token carrying an opted-in claims set whose
// revalidation time is the given duration in the past.
func staleRevalToken(t *testing.T, s *Steranko, subject string, age time.Duration) string {
	t.Helper()
	token, err := s.CreateJWT(&testRevalClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject},
		RevalidatedAt:    time.Now().Add(-age).Unix(),
	})
	require.Nil(t, err)
	return token
}

// notFoundUserService wraps a UserService and forces LoadBySubject to report a
// "not found" error, simulating a user who has been deleted/revoked.
type notFoundUserService struct {
	UserService
}

func (s notFoundUserService) LoadBySubject(subject string, user User) error {
	return derp.NotFound("test", "user not found")
}

// dbErrorUserService wraps a UserService and forces LoadBySubject to report a
// non-NotFound (transient) error, simulating a database outage.
type dbErrorUserService struct {
	UserService
}

func (s dbErrorUserService) LoadBySubject(subject string, user User) error {
	return errors.New("database is on fire")
}

// TestRevalidate_FreshToken confirms that a token still inside the window is
// left untouched: no re-load, no new cookie.
func TestRevalidate_FreshToken(t *testing.T) {

	s := getTestSteranko()
	claims := revalClaims("michael@jackson.com", 1*time.Minute) // well inside the 10m default

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.revalidate(ctx, claims))
	require.Empty(t, rec.Result().Cookies(), "a fresh token must not be re-minted")
}

// TestRevalidate_StaleCookie_ReMints confirms that a stale cookie session is
// re-verified against the UserService and a fresh cookie is written.
func TestRevalidate_StaleCookie_ReMints(t *testing.T) {

	s := getTestSteranko()
	claims := revalClaims("michael@jackson.com", 30*time.Minute) // past the 10m default

	// A request that carries an Authorization cookie is re-mintable.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "stale-token"})
	ctx, rec := echoContextWithRecorder(t, req)

	require.Nil(t, s.revalidate(ctx, claims))

	cookie := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, cookie, "a stale cookie session must be re-minted")
	require.NotEmpty(t, cookie.Value)
}

// TestRevalidate_StaleBearer_NoReMint confirms that a stale Bearer/header
// session is still re-verified, but no cookie is written (it cannot be).
func TestRevalidate_StaleBearer_NoReMint(t *testing.T) {

	s := getTestSteranko()
	claims := revalClaims("michael@jackson.com", 30*time.Minute)

	// A request with NO cookie (Bearer-style) cannot be re-minted.
	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.revalidate(ctx, claims), "a still-valid Bearer user must pass revalidation")
	require.Empty(t, rec.Result().Cookies(), "a Bearer session has no cookie to re-mint")
}

// TestRevalidate_RevokedUser_Rejects confirms fail-closed behavior when the user
// has been deleted: a "not found" must reject the request.
func TestRevalidate_RevokedUser_Rejects(t *testing.T) {

	s := getTestSteranko()
	s.userService = notFoundUserService{UserService: s.userService}
	claims := revalClaims("michael@jackson.com", 30*time.Minute)

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	err := s.revalidate(ctx, claims)
	require.NotNil(t, err)
	require.True(t, derp.IsForbidden(err), "a revoked user must be rejected (forbidden)")
	require.Empty(t, rec.Result().Cookies(), "no cookie should be written for a rejected session")
}

// TestRevalidate_DatabaseError_Rejects confirms fail-closed behavior on a
// transient error: even though we cannot prove the user is gone, we reject.
func TestRevalidate_DatabaseError_Rejects(t *testing.T) {

	s := getTestSteranko()
	s.userService = dbErrorUserService{UserService: s.userService}
	claims := revalClaims("michael@jackson.com", 30*time.Minute)

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	err := s.revalidate(ctx, claims)
	require.NotNil(t, err, "a transient error must fail closed")
	require.False(t, derp.IsNotFound(err), "a transient error is distinct from a revoked user")
	require.Empty(t, rec.Result().Cookies())
}

// TestRevalidate_StaleNoSubject_Rejects confirms that a session which opted in to
// revalidation and is stale, but carries no "sub", cannot be revalidated and is
// rejected (fail closed). Opting in is an explicit promise to be re-checkable.
func TestRevalidate_StaleNoSubject_Rejects(t *testing.T) {

	s := getTestSteranko()

	// Opted in (stale) but with an empty subject.
	claims := testRevalClaims{
		RevalidatedAt: time.Now().Add(-30 * time.Minute).Unix(),
	}

	ctx := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))

	err := s.revalidate(ctx, claims)
	require.NotNil(t, err)
	require.True(t, derp.IsForbidden(err), "a stale opted-in session with no subject cannot be revalidated")
}

// TestRevalidate_NotRevalidatable_Skips confirms that claims which do not
// implement Revalidatable are exempt: revalidation is skipped, never rejected.
// This is how non-User sessions (guests, API tokens) opt out.
func TestRevalidate_NotRevalidatable_Skips(t *testing.T) {

	s := getTestSteranko()
	claims := jwt.MapClaims{"sub": "michael@jackson.com"} // does not implement Revalidatable

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.revalidate(ctx, claims), "claims that do not opt in are exempt from revalidation")
	require.Empty(t, rec.Result().Cookies())
}

// TestRevalidate_OptedInNoTime_Skips confirms that a claims type which implements
// Revalidatable but reports no revalidation time (hasReval == false) is also
// exempt and skipped rather than rejected.
func TestRevalidate_OptedInNoTime_Skips(t *testing.T) {

	s := getTestSteranko()

	claims := testRevalClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "michael@jackson.com"},
		// RevalidatedAt left zero: implements the interface, but no timestamp set
	}

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.revalidate(ctx, claims), "an opted-in session with no timestamp is skipped")
	require.Empty(t, rec.Result().Cookies())
}

// TestRevalidate_Disabled confirms that a non-positive interval turns the
// feature off entirely, even for an ancient token.
func TestRevalidate_Disabled(t *testing.T) {

	s := getTestSteranko()
	s.WithOptions(WithRevalidationInterval(0))
	claims := revalClaims("michael@jackson.com", 100*time.Hour)

	ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.revalidate(ctx, claims), "a zero interval disables revalidation")
	require.Empty(t, rec.Result().Cookies())
}

// TestWithRevalidationInterval confirms the option overrides the default, and
// that New seeds the default.
func TestWithRevalidationInterval(t *testing.T) {

	// Default is applied by New.
	{
		s := getTestSteranko()
		require.Equal(t, defaultRevalidationInterval, s.revalidationInterval)
	}

	// The option overrides the default.
	{
		s := getTestSteranko()
		s.WithOptions(WithRevalidationInterval(2 * time.Minute))
		require.Equal(t, 2*time.Minute, s.revalidationInterval)
	}
}

// TestRevalidate_RealToken_RoundTrip mints a real signed token (so "sub" and
// "srev" round-trip through JSON exactly as they would in production) and
// confirms a stale one is re-verified and re-minted via the cookie path.
func TestRevalidate_RealToken_RoundTrip(t *testing.T) {

	s := getTestSteranko()
	s.userService = revalUserService{UserService: s.userService}

	token := staleRevalToken(t, s, "michael@jackson.com", 30*time.Minute)

	// Parse it back the same way GetAuthorization does, then revalidate.
	parsed, err := s.GetAuthorization(cookieRequestFrom([]*http.Cookie{{Name: "Authorization", Value: token}}))
	require.Nil(t, err)

	// The parsed claims must implement Revalidatable and report a stale time.
	revalidatable, ok := parsed.(Revalidatable)
	require.True(t, ok, "parsed claims must implement Revalidatable")
	at, present := revalidatable.GetRevalidationTime()
	require.True(t, present, "srev must survive the JSON round-trip")
	require.Greater(t, time.Since(at), s.revalidationInterval, "the round-tripped session must read as stale")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: token})
	ctx, rec := echoContextWithRecorder(t, req)

	require.Nil(t, s.revalidate(ctx, parsed))
	require.NotNil(t, findCookie(t, rec.Result().Cookies(), "Authorization"), "a real stale token must be re-minted")
}

// carrierClaims opts in to revalidation AND implements SessionCarrier, carrying a session-scoped
// Flag (standing in for the masquerade marker) that must survive a re-mint.
type carrierClaims struct {
	jwt.RegisteredClaims
	RevalidatedAt int64 `json:"srev,omitempty"`
	Flag          bool  `json:"flag,omitempty"`
}

func (c carrierClaims) GetRevalidationTime() (time.Time, bool) {
	if c.RevalidatedAt == 0 {
		return time.Time{}, false
	}
	return time.Unix(c.RevalidatedAt, 0), true
}

func (c *carrierClaims) CarryForwardSessionState(previous jwt.Claims) {
	if prev, ok := previous.(*carrierClaims); ok {
		c.Flag = prev.Flag
	}
}

// carrierUserService rebuilds claims as *carrierClaims whose Flag defaults to false, so a
// surviving true Flag can only come from CarryForwardSessionState.
type carrierUserService struct {
	UserService
}

func (carrierUserService) NewClaims() jwt.Claims { return &carrierClaims{} }

func (carrierUserService) Claims(user User) (jwt.Claims, error) {
	return &carrierClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: user.GetUsername()},
		RevalidatedAt:    time.Now().Unix(),
		// Flag intentionally omitted: a fresh DB rebuild does not know the session state.
	}, nil
}

func (carrierUserService) LoadBySubject(subject string, user User) error {
	user.SetUsername(subject)
	return nil
}

// TestRevalidate_CarriesForwardSessionState confirms that a session-scoped claim (the masquerade
// marker, modeled as Flag) survives a revalidation re-mint that the user-record rebuild drops.
func TestRevalidate_CarriesForwardSessionState(t *testing.T) {

	s := getTestSteranko()
	s.userService = carrierUserService{UserService: s.userService}

	// A stale, opted-in session whose Flag (masquerade marker) is set.
	previous := &carrierClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "michael@jackson.com"},
		RevalidatedAt:    time.Now().Add(-30 * time.Minute).Unix(),
		Flag:             true,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "stale-token"})
	ctx, rec := echoContextWithRecorder(t, req)

	require.Nil(t, s.revalidate(ctx, previous))

	// The re-minted cookie must still carry the Flag.
	cookie := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, cookie)

	reminted, err := s.parseToken(cookie.Value)
	require.Nil(t, err)
	carried, ok := reminted.(*carrierClaims)
	require.True(t, ok)
	require.True(t, carried.Flag, "the session-scoped flag must be carried forward across revalidation")
}

// TestMiddleware_RevokedUser_Rejects confirms the wired-up middleware rejects a
// request whose stale token belongs to a now-revoked user (fail closed).
func TestMiddleware_RevokedUser_Rejects(t *testing.T) {

	s := getTestSteranko()
	// Opt-in claims (via revalUserService) whose LoadBySubject reports "not found".
	s.userService = notFoundUserService{UserService: revalUserService{UserService: s.userService}}

	token := staleRevalToken(t, s, "michael@jackson.com", 30*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: token})
	ctx, _ := echoContextWithRecorder(t, req)

	// The handler must NOT run, because the middleware rejects first.
	handlerRan := false
	handler := s.Middleware(func(c echo.Context) error {
		handlerRan = true
		return nil
	})

	err := handler(ctx)
	require.NotNil(t, err)
	require.True(t, derp.IsForbidden(err))
	require.False(t, handlerRan, "a rejected session must never reach the handler")
}

// TestMiddleware_FreshSession_Passes confirms the middleware lets a fresh,
// valid session through to the handler untouched.
func TestMiddleware_FreshSession_Passes(t *testing.T) {

	s := getTestSteranko()
	s.userService = revalUserService{UserService: s.userService}

	token := staleRevalToken(t, s, "michael@jackson.com", 0) // verified "now"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: token})
	ctx, _ := echoContextWithRecorder(t, req)

	handlerRan := false
	handler := s.Middleware(func(c echo.Context) error {
		handlerRan = true
		return nil
	})

	require.Nil(t, handler(ctx))
	require.True(t, handlerRan, "a fresh valid session must reach the handler")
}

// TestMiddleware_Anonymous_Passes confirms an unauthenticated request (no token)
// is not rejected by revalidation; it simply has nothing to revalidate.
func TestMiddleware_Anonymous_Passes(t *testing.T) {

	s := getTestSteranko()

	ctx, _ := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

	handlerRan := false
	handler := s.Middleware(func(c echo.Context) error {
		handlerRan = true
		return nil
	})

	require.Nil(t, handler(ctx))
	require.True(t, handlerRan, "an anonymous request must pass through revalidation")
}

// TestRequestHasAuthCookie confirms the cookie-vs-header detection that decides
// whether a session can be re-minted.
func TestRequestHasAuthCookie(t *testing.T) {

	// A request carrying the Authorization cookie is re-mintable.
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: "x"})
		require.True(t, requestHasAuthCookie(req))
	}

	// A request with only a Bearer header is not.
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer x")
		require.False(t, requestHasAuthCookie(req))
	}
}

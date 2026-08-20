package steranko

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/benpate/derp"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// TestMiddleware_Factory confirms the multi-tenant Middleware resolves a
// Steranko instance via the factory and wraps the context for the next handler.
func TestMiddleware_Factory(t *testing.T) {

	s := getTestSteranko()
	mw := Middleware(staticFactory{steranko: s})

	called := false
	handler := mw(func(ctx echo.Context) error {
		called = true
		// The downstream handler must receive a *steranko.Context.
		_, ok := ctx.(*Context)
		require.True(t, ok, "next handler should receive a *steranko.Context")
		return nil
	})

	ctx := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Nil(t, handler(ctx))
	require.True(t, called)
}

// TestMiddleware_FactoryError confirms a factory error short-circuits the chain
// and the next handler is never called.
func TestMiddleware_FactoryError(t *testing.T) {

	boom := errors.New("no tenant")
	mw := Middleware(staticFactory{err: boom})

	called := false
	handler := mw(func(ctx echo.Context) error {
		called = true
		return nil
	})

	ctx := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))
	err := handler(ctx)

	require.Equal(t, boom, err)
	require.False(t, called, "next handler must not run when the factory fails")
}

// TestSterankoMiddleware confirms the instance-bound Middleware wraps the
// context and calls the next handler.
func TestSterankoMiddleware(t *testing.T) {

	s := getTestSteranko()

	called := false
	handler := s.Middleware(func(ctx echo.Context) error {
		called = true
		wrapped, ok := ctx.(*Context)
		require.True(t, ok)
		require.Same(t, s, wrapped.steranko)
		return nil
	})

	ctx := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Nil(t, handler(ctx))
	require.True(t, called)
}

// TestMiddleware_Factory_RevalidatesRevokedSession confirms that the multi-tenant
// Middleware applies the SAME fail-closed revalidation as the instance-bound one.
// A user deleted since their token was minted must be rejected through EITHER entry
// point; a version that re-implements the chain instead of delegating drops the
// revalidation step and admits them.
func TestMiddleware_Factory_RevalidatesRevokedSession(t *testing.T) {

	s := getTestSteranko()
	s.userService = notFoundUserService{revalUserService{s.userService}} // the user has been deleted

	// A session that opted in to revalidation, and is well past the 10-minute window.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "Authorization",
		Value: staleRevalToken(t, s, "michael@jackson.com", 30*time.Minute),
	})

	called := false
	handler := Middleware(staticFactory{steranko: s})(func(ctx echo.Context) error {
		called = true
		return nil
	})

	err := handler(echoContext(t, req))

	require.NotNil(t, err, "a revoked session must be rejected")
	require.True(t, derp.IsForbidden(err))
	require.False(t, called, "a revoked user must never reach the handler")
}

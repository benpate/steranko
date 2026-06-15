package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/benpate/steranko/plugin/hash"
	"github.com/labstack/echo/v4"
)

// echoContext builds an echo.Context for the given request, backed by a fresh
// httptest recorder. The recorder is returned so callers can inspect the
// response (e.g. cookies that were written).
func echoContextWithRecorder(t *testing.T, req *http.Request) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	return echo.New().NewContext(req, rec), rec
}

// echoContext is a convenience wrapper around echoContextWithRecorder for
// callers that do not need the recorder.
func echoContext(t *testing.T, req *http.Request) echo.Context {
	t.Helper()
	ctx, _ := echoContextWithRecorder(t, req)
	return ctx
}

// plaintextHasher returns the (insecure) Plaintext hasher used throughout the
// tests so that signin/authentication paths run quickly and deterministically.
func plaintextHasher() PasswordHasher {
	return hash.Plaintext{}
}

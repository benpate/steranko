package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNilSigninService confirms the no-op signin service never reports a lockout
// and tolerates calls with any arguments (including a nil request).
func TestNilSigninService(t *testing.T) {

	service := NilSigninService{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// The no-op service must never lock an account.
	require.False(t, service.IsSigninLocked(req, "anyone@example.com"))
	require.False(t, service.IsSigninLocked(nil, ""))

	// Success/Failure are no-ops and must not panic.
	require.NotPanics(t, func() {
		service.SigninSuccess(req, "anyone@example.com")
		service.SigninFailure(req, "anyone@example.com")
		service.SigninSuccess(nil, "")
		service.SigninFailure(nil, "")
	})
}

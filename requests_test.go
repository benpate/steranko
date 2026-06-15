package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestApproveRequest documents the current behavior of ApproveRequest, which is
// a placeholder that approves every request. This test will flag the change in
// behavior when real filtering rules are added.
func TestApproveRequest(t *testing.T) {

	s := getTestSteranko()
	ctx := echoContext(t, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Nil(t, s.ApproveRequest(ctx))
}

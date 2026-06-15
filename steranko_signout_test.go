package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignOut_NoBackup confirms that signing out with no backup cookie deletes
// the primary cookie and reports that there was no backup.
func TestSignOut_NoBackup(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "some-token"})
	ctx, rec := echoContextWithRecorder(t, req)

	hasBackup := s.SignOut(ctx)

	require.False(t, hasBackup)

	// The Authorization cookie should be cleared (empty value). The source sets
	// MaxAge:0, which net/http encodes as "no Max-Age attribute".
	cookie := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, cookie)
	require.Empty(t, cookie.Value)
	require.Equal(t, 0, cookie.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.True(t, cookie.HttpOnly)
}

// TestSignOut_WithBackup confirms that a non-empty backup cookie is restored to
// the primary cookie, the backup is deleted, and the function reports true.
func TestSignOut_WithBackup(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: "previous-token"})
	ctx, rec := echoContextWithRecorder(t, req)

	hasBackup := s.SignOut(ctx)

	require.True(t, hasBackup)

	cookies := rec.Result().Cookies()

	// The primary cookie must be restored to the backup value.
	restored := findCookie(t, cookies, "Authorization")
	require.NotNil(t, restored)
	require.Equal(t, "previous-token", restored.Value)

	// The backup cookie must be deleted (cleared to an empty value).
	deletedBackup := findCookie(t, cookies, "Authorization-backup")
	require.NotNil(t, deletedBackup)
	require.Empty(t, deletedBackup.Value)
	require.Equal(t, 0, deletedBackup.MaxAge)
}

// TestSignOut_EmptyBackup confirms that an empty backup cookie is ignored (it
// cannot be used to "restore" a session), and the primary cookie is deleted.
func TestSignOut_EmptyBackup(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: ""})
	ctx, rec := echoContextWithRecorder(t, req)

	hasBackup := s.SignOut(ctx)

	require.False(t, hasBackup, "an empty backup cookie must not count as a backup")

	// The primary cookie is deleted (not restored from an empty backup).
	primary := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, primary)
	require.Empty(t, primary.Value)
	require.Equal(t, 0, primary.MaxAge)
}

// TestSignOut_TLS confirms the deleted cookie is marked Secure on a TLS request.
func TestSignOut_TLS(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	ctx, rec := echoContextWithRecorder(t, req)

	require.False(t, s.SignOut(ctx))

	// SignOut uses cookieName(request); on TLS that is the __Host- prefixed name.
	cookie := findCookie(t, rec.Result().Cookies(), "__Host-Authorization")
	require.NotNil(t, cookie)
	require.True(t, cookie.Secure)
}

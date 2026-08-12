package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// backupToken mints a real signed session token carrying the given subject, suitable for
// placing in an "-backup" cookie (a restore re-verifies it, so it must be a genuine JWT).
func backupToken(t *testing.T, s *Steranko, subject string) string {
	t.Helper()
	token, err := s.CreateJWT(jwt.MapClaims{"sub": subject})
	require.Nil(t, err)
	return token
}

// TestSignOut_NoBackup confirms that signing out with no backup cookie deletes the
// primary cookie and reports that there was no backup.
func TestSignOut_NoBackup(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "some-token"})
	ctx, rec := echoContextWithRecorder(t, req)

	hasBackup := s.SignOut(ctx)

	require.False(t, hasBackup)

	// The Authorization cookie should be cleared (empty value) and expired immediately.
	cookie := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, cookie)
	require.Empty(t, cookie.Value)
	require.True(t, cookie.MaxAge < 0)
	require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
	require.True(t, cookie.HttpOnly)
}

// TestSignOut_ValidBackup_Restores confirms that a backup whose token re-verifies is restored
// to the primary cookie, the backup is deleted, and the function reports true.
func TestSignOut_ValidBackup_Restores(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: backupToken(t, s, "michael@jackson.com")})
	ctx, rec := echoContextWithRecorder(t, req)

	hasBackup := s.SignOut(ctx)

	require.True(t, hasBackup)

	cookies := rec.Result().Cookies()

	// The primary cookie must be re-minted from the re-verified backup session, and it
	// must parse back to the restored user.
	restored := findCookie(t, cookies, "Authorization")
	require.NotNil(t, restored)
	require.NotEmpty(t, restored.Value)

	claims, err := s.GetAuthorization(cookieRequestFrom([]*http.Cookie{{Name: "Authorization", Value: restored.Value}}))
	require.Nil(t, err)
	require.Equal(t, "michael@jackson.com", claims.(jwt.MapClaims)["username"])

	// The backup cookie must be deleted (cleared and expired).
	deletedBackup := findCookie(t, cookies, "Authorization-backup")
	require.NotNil(t, deletedBackup)
	require.Empty(t, deletedBackup.Value)
	require.True(t, deletedBackup.MaxAge < 0)
}

// TestSignOut_InvalidBackup_FullSignOut confirms that a backup token that cannot be
// parsed/verified is NOT restored: the browser is fully signed out and both cookies deleted.
func TestSignOut_InvalidBackup_FullSignOut(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: "not-a-valid-jwt"})
	ctx, rec := echoContextWithRecorder(t, req)

	require.False(t, s.SignOut(ctx), "an unverifiable backup must not be restored")

	cookies := rec.Result().Cookies()

	primary := findCookie(t, cookies, "Authorization")
	require.NotNil(t, primary)
	require.Empty(t, primary.Value)
	require.True(t, primary.MaxAge < 0)

	backup := findCookie(t, cookies, "Authorization-backup")
	require.NotNil(t, backup)
	require.Empty(t, backup.Value)
	require.True(t, backup.MaxAge < 0)
}

// TestSignOut_RevokedBackupUser_FullSignOut is the key security check: a validly-signed backup
// whose user was deleted/demoted must FAIL revalidation and result in a full sign-out.
func TestSignOut_RevokedBackupUser_FullSignOut(t *testing.T) {

	s := getTestSteranko()

	// Mint a genuinely-signed backup token FIRST (while the user service still resolves),
	// then swap in a service whose LoadBySubject reports the user is gone.
	token := backupToken(t, s, "michael@jackson.com")
	s.userService = notFoundUserService{UserService: s.userService}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: token})
	ctx, rec := echoContextWithRecorder(t, req)

	require.False(t, s.SignOut(ctx), "a revoked backup user must not be restored")

	cookies := rec.Result().Cookies()

	primary := findCookie(t, cookies, "Authorization")
	require.NotNil(t, primary)
	require.Empty(t, primary.Value)

	backup := findCookie(t, cookies, "Authorization-backup")
	require.NotNil(t, backup)
	require.Empty(t, backup.Value)
}

// TestSignOut_EmptyBackup confirms that an empty backup cookie is ignored (it cannot be
// used to "restore" a session), and the primary cookie is deleted.
func TestSignOut_EmptyBackup(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "current-token"})
	req.AddCookie(&http.Cookie{Name: "Authorization-backup", Value: ""})
	ctx, rec := echoContextWithRecorder(t, req)

	require.False(t, s.SignOut(ctx), "an empty backup cookie must not count as a backup")

	primary := findCookie(t, rec.Result().Cookies(), "Authorization")
	require.NotNil(t, primary)
	require.Empty(t, primary.Value)
	require.True(t, primary.MaxAge < 0)
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

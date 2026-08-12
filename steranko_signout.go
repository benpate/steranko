package steranko

import (
	"github.com/labstack/echo/v4"
)

// SignOut ends the caller's session. It returns TRUE if a backed-up (masquerade) session was
// restored -- the caller "popped back" -- and FALSE if the browser is now fully signed out.
func (s *Steranko) SignOut(ctx echo.Context) bool {

	name := cookieName(ctx.Request())
	backupName := name + "-backup"

	// A backup is trusted only after it passes the SAME fail-closed revalidation as any other
	// session (see restoreBackup). If it re-verifies, restore it and drop the backup slot.
	if s.restoreBackup(ctx, backupName) {
		deleteCookie(ctx, backupName)
		return true
	}

	// Otherwise, fully sign out: delete BOTH the active and backup cookies so nothing can be
	// restored later.
	deleteCookie(ctx, name)
	deleteCookie(ctx, backupName)
	return false
}

// restoreBackup re-verifies the named backup cookie against the UserService and, on success,
// installs the rebuilt claims as the active session cookie. It is fail-closed.
func (s *Steranko) restoreBackup(ctx echo.Context, backupName string) bool {

	// Read the backup cookie. Absence is the common case (no masquerade in progress).
	backupCookie, err := ctx.Cookie(backupName)

	if err != nil {
		return false
	}

	// An empty backup cannot be used to restore a session.
	if backupCookie.Value == "" {
		return false
	}

	// Parse + validate the backup token (signature, signing method, expiry).
	previousClaims, err := s.parseToken(backupCookie.Value)

	if err != nil {
		return false
	}

	// Re-verify against the UserService (reload user, rebuild claims), fail-closed. This
	// is the SAME check applied to any session at revalidation, so a backed-up owner who
	// was deleted or demoted during the masquerade cannot be restored.
	freshClaims, err := s.reissueClaims(previousClaims)

	if err != nil {
		return false
	}

	// Install the re-verified session as the active cookie. SetCookie writes in place and
	// does NOT create a new backup, so the session stack does not grow.
	if err := s.SetCookie(ctx, freshClaims); err != nil {
		return false
	}

	return true
}

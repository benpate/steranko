package steranko

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// SignOut implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function.
// It returns TRUE if the user had a backup cookie that has been restored,
// and FALSE if the user is now completely signed out.
func (s *Steranko) SignOut(ctx echo.Context) bool {

	// Default setting is to simply delete the login session cookie
	// and report that there was no backup cookie.
	request := ctx.Request()
	name := cookieName(request)
	deleteName := name
	backupName := name + "-backup"
	hasBackup := false

	// Look for an "-backup" cookie.  If present, restore it to the primary cookie, and
	// delete the original.
	if backupCookie, err := request.Cookie(backupName); err == nil {

		// The backup cookie cannot be empty...
		if backupCookie.Value != "" {
			restoredCookie := copyCookie(backupCookie)
			restoredCookie.Name = name
			ctx.SetCookie(&restoredCookie)

			deleteName = backupName
			hasBackup = true
		}
	}

	// Delete the remaining cookie (either original or backup)
	ctx.SetCookie(&http.Cookie{
		Name:     deleteName,              // Get the Cookie name to use for this context.
		Value:    "",                      // Erase the value of the cookie
		MaxAge:   0,                       // Expires the cookie immediately
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
	})

	return hasBackup
}

package steranko

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// SignOut implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function.
func (s *Steranko) SignOut(ctx echo.Context) error {

	ctx.SetCookie(&http.Cookie{
		Name:     cookieName(ctx.Request()), // Get the Cookie name to use for this context.
		Value:    "",                        // Erase the value of the cookie
		MaxAge:   0,                         // Expires the cookie immediately
		Path:     "/",                       // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),               // Set secure cookies if we're on a secure connection
		HttpOnly: true,                      // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode,   // Strict same-site policy prevents cookies from being used by other sites.
	})

	return nil
}

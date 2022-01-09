package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
)

// SigniI implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function if
// you want to extend its functionality.  If the signin is successful
// it automatically sets the "Authorization" cookie in the user's browser.
func (s *Steranko) SignIn(ctx echo.Context) error {

	var txn SigninTransaction

	if err := ctx.Bind(&txn); err != nil {
		return derp.New(500, "steranko.Signin", "Invalid Request. Please try again later.")
	}

	user := s.UserService.New()

	// try to authenticate the user
	if err := s.Authenticate(txn.Username, txn.Password, user); err != nil {
		sleepRandom(1000, 3000)
		return derp.New(derp.CodeForbiddenError, "steranko.Signin", "Invalid username/password.  Please try again.")
	}

	sleepRandom(500, 1500)

	// Try to create a JWT token
	token, err := s.createJWT(user)

	if err != nil {
		return derp.New(derp.CodeInternalError, "steranko.Signin", "Internal error.  Please try again later.")
	}

	ctx.SetCookie(&http.Cookie{
		Name:     cookieName(ctx),
		Value:    token,                   // Set the cookie's value
		MaxAge:   63072000,                // Max-Age is 2 YEARS (60s * 60min * 24h * 365d * 2y)
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	})

	return nil
}

// SignOut implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function.
func (s *Steranko) SignOut(ctx echo.Context) error {

	ctx.SetCookie(&http.Cookie{
		Name:     cookieName(ctx),         // Get the Cookie name to use for this context.
		Value:    "",                      // Erase the value of the cookie
		MaxAge:   0,                       // Expires the cookie immediately
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
	})

	return nil
}

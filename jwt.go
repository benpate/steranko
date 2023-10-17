package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// CreateCertificate creates a new JWT token for the provided user.
func (s *Steranko) CreateCertificate(ctx echo.Context, user User) error {

	// (short) random sleep to thwart timing attacks
	sleepRandom(500, 1500)

	// Set up a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = user.Claims()

	keyID, key := s.KeyService.NewJWTKey()
	token.Header["kid"] = keyID

	// Generate encoded token and send it as response.
	signedString, err := token.SignedString(key)

	if err != nil {
		return derp.Wrap(err, "steranko.PostSigninTransaction", "Error Signing JWT Token")
	}

	// Set a cookie in the response context
	ctx.SetCookie(&http.Cookie{
		Name:     cookieName(ctx),
		Value:    signedString,            // Set the cookie's value
		MaxAge:   63072000,                // Max-Age is 2 YEARS (60s * 60min * 24h * 365d * 2y)
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	})

	// Success!
	return nil
}

// cookieName returns the correct cookie name to use, based on the kind of connection.
// If connecting via HTTP, then "Authorization" is used.
// If connecting via SSL, then "__Host-Authorization" is used so that the cookie is "domain locked".  See [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes]
func cookieName(ctx echo.Context) string {

	// If this is a secure domain...
	if ctx.IsTLS() {
		// Use a cookie name that can only be set on an SSL connection, and is "domain-locked"
		return "__Host-Authorization"
	}

	return "Authorization"
}

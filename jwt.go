package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// createJWT creates a new JWT token for the provided user.
// TODO: include additional configuration options when defined.
func (s *Steranko) createJWT(user User) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = user.Claims()

	keyID, key := s.KeyService.NewJWTKey()

	token.Header["kid"] = keyID

	// Generate encoded token and send it as response.
	signedString, errr := token.SignedString(key)

	if errr != nil {
		return "", derp.Wrap(errr, "steranko.PostSigninTransaction", "Error Signing JWT Token")
	}

	return signedString, nil
}

// setJWT applies a JWT token to the response context, using configuration
// options to determine if a header value or a cookie should be used.
func (s *Steranko) setJWT(ctx echo.Context, token string) {

	// Set Cookies
	ctx.SetCookie(&http.Cookie{
		Name:     "Authorization",
		Value:    token,                   // Set the cookie's value
		MaxAge:   63072000,                // Max-Age is 2 YEARS (60s * 60min * 24h * 365d * 2y)
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	})

	/* Remove old code for now. May want to re-enable authentication tokens in the header at some point in the future.

	// Return Tokens??
	location, name := list.Split(s.Config.Token, ":")

	if location == "cookie" {
		ctx.SetCookie(&http.Cookie{
			Name:  name,
			Value: token,
		})
	} else {
		ctx.Response().Header().Set(name, token)
	}
	*/
}

package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/list"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// createJWT creates a new JWT token for the provided user.
// TODO: include additional configuration options when defined.
func (s *Steranko) createJWT(user User) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims(user.Claims())

	// Generate encoded token and send it as response.
	signedString, errr := token.SignedString([]byte("secret")) // TODO: this *MUST* come from a secure source.

	if errr != nil {
		return "", derp.Wrap(errr, "steranko.PostSigninTransaction", "Error Signing JWT Token")
	}

	return signedString, nil
}

// setJWT applies a JWT token to the response context, using configuration
// options to determine if a header value or a cookie should be used.
func (s *Steranko) setJWT(ctx echo.Context, token string) {

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
}

package steranko

import (
	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Context extends the echo context with an authenticated JWT Token.
type Context struct {
	steranko *Steranko
	claims   jwt.Claims
	echo.Context
}

// Authorization retrieves the JWT token claims from the context.
// Values are cached so we don't re-parse the JWT cookie with mutiple calls.
func (ctx *Context) Authorization() (jwt.Claims, error) {

	// If we have already cached a claims value, then just use that
	if ctx.claims != nil {
		return ctx.claims, nil
	}

	// Get the claims from GetAuthorization()
	claims, err := ctx.steranko.GetAuthorization(ctx.Request())

	if err != nil {
		return nil, derp.Wrap(err, "steranko.Context.Authorization", "Error parsing token")
	}

	// Save the claims in the context (for next time, maybe) and return
	ctx.claims = claims
	return ctx.claims, nil
}

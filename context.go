package steranko

import (
	"github.com/benpate/data"
	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Context extends the echo context with an authenticated JWT Token.
type Context[T jwt.Claims] struct {
	steranko        *Steranko[T]
	session         data.Session
	claims          T
	claimsPopulated bool
	echo.Context
}

// Authorization retrieves the JWT token claims from the context.
// Values are cached so we don't re-parse the JWT cookie with mutiple calls.
func (ctx *Context[T]) Authorization() (T, error) {

	const location = "steranko.Context.Authorization"

	// If we have already cached a claims value, then just use that
	if ctx.claimsPopulated {
		return ctx.claims, nil
	}

	// Get the claims from GetAuthorization()
	claims, err := ctx.steranko.GetAuthorization(ctx.Request(), ctx.session)

	if err != nil {
		var nilClaims T
		return nilClaims, derp.Wrap(err, location, "Error parsing token")
	}

	// Save the claims in the context (for next time, maybe) and return
	ctx.claims = claims
	ctx.claimsPopulated = true
	return ctx.claims, nil
}

func (ctx *Context[T]) Session() data.Session {
	return ctx.session
}

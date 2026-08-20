package steranko

import (
	"github.com/labstack/echo/v4"
)

// Middleware is a standalone middleware that works for multi-tenant
// environments, where you may need to use a factory to load the specific
// steranko settings depending on the domain being called.
func Middleware(factory Factory) echo.MiddlewareFunc {

	// this is the middleware function
	return func(next echo.HandlerFunc) echo.HandlerFunc {

		// this handles the specific request
		return func(ctx echo.Context) error {

			// find the correct steranko instance
			s, err := factory.Steranko(ctx)

			// handle errors (if necessary)
			if err != nil {
				return err
			}

			// Hand off to the instance middleware so that BOTH entry points apply an identical
			// chain: request approval, then fail-closed revalidation of an aged session. This
			// used to be re-implemented here, which silently omitted revalidation and let a
			// deleted or demoted user keep their session in a multi-tenant deployment.
			return s.Middleware(next)(ctx)
		}
	}
}

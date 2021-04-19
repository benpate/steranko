package steranko

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

func (s *Steranko) Middleware(required bool) echo.MiddlewareFunc {

	return func(next echo.HandlerFunc) echo.HandlerFunc {

		return func(ctx echo.Context) error {

			if cookie, err := ctx.Cookie("Authorization"); err == nil {

				claims := s.UserService.NewClaims()

				if token, err := jwt.ParseWithClaims(cookie.Value, claims, s.KeyService.FindJWTKey); err == nil {

					// TODO: Token Expiration / Renewal
					// TODO: Errors on failed token parsing?

					return next(Context{
						Context: ctx,
						Token:   token,
					})
				}
			}

			// Fall through means we do not have a valid JWT token
			// If signin is required, then return an error.
			if required {
				return echo.ErrForbidden
			}

			return next(ctx)
		}
	}
}

package steranko

import (
	"github.com/labstack/echo/v4"
)

// Middleware wraps the original echo context with the Steranko context.
func (s *Steranko) Middleware(next echo.HandlerFunc) echo.HandlerFunc {

	return func(ctx echo.Context) error {

		return next(Context{
			Context: ctx,
		})
	}
}

package steranko

import "github.com/labstack/echo/v4"

// Middleware wraps the original echo context with the Steranko context.
func (s *Steranko) Middleware(next echo.HandlerFunc) echo.HandlerFunc {

	return func(ctx echo.Context) error {

		// Verify that the request is valid
		if err := s.ApproveRequest(ctx); err != nil {
			return err
		}

		return next(&Context{
			Context:  ctx,
			steranko: s,
		})
	}
}

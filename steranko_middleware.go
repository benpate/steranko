package steranko

// REMOVED BECAUSE THIS NO LONGER WORKS WITH THE FACTORY/SESSION API
/*
// Middleware wraps the original echo context with the Steranko context.
func (s *Steranko[T]) Middleware(next echo.HandlerFunc) echo.HandlerFunc {

	return func(ctx echo.Context) error {

		// Verify that the request is valid
		// if err := s.ApproveRequest(ctx); err != nil {
		// 	return err
		// }

		return next(&Context[T]{
			Context:  ctx,
			steranko: s,
		})
	}
}
*/

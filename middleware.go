package steranko

// REMOVED BECAUSE THIS NO LONGER WORKS WITH THE SESSION API
/*
// Middleware is a standalone middleware that works for multi-tenant
// environments, where you may need to use a factory to load the specific
// steranko settings depending on the domain being called.
func Middleware[T jwt.Claims](factory Factory[T]) echo.MiddlewareFunc {

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

			// REMOVING THIS (FOR NOW) BECAUSE IT'S A NO-OP
			// Verify that the request is valid
			// if err := s.ApproveRequest(ctx); err != nil {
			// 	return err
			// }

			// call the next function in the chain, now
			// using a Steranko context instead of the original
			return next(&Context[T]{
				Context:  ctx,
				steranko: s,
			})
		}
	}
}
*/

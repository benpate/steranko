package steranko

import (
	"net/http"
	"time"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Revalidatable is implemented by claims that opt in to session revalidation.
// GetRevalidationTime returns the moment the session was last verified, and a
// boolean reporting whether that moment is set. Claims that do not implement
// this interface (or that report FALSE) are exempt from revalidation entirely,
// which is how non-User sessions (guests, API tokens, etc.) opt out.
type Revalidatable interface {
	GetRevalidationTime() (time.Time, bool)
}

// revalidate re-verifies an authenticated session against the UserService when
// its token has aged past the configured revalidation interval. This lets the
// server catch users who have been deleted, moved, or had their permissions
// changed since the long-lived token was issued.
//
// On success for a COOKIE session, a fresh token is minted and the cookie is
// re-set, so the window slides forward. A BEARER/header session is re-checked
// but cannot be re-issued (the server has no channel to mutate a client-held
// token), so it is re-verified on every request past the window.
//
// RULE: This is fail-closed. Any failure to re-load the user or rebuild their
// claims rejects the request, even a transient database error. A revoked user
// must never be honored on the strength of a stale token alone.
func (s *Steranko) revalidate(ctx echo.Context, claims jwt.Claims) error {

	const location = "steranko.revalidate"

	// A non-positive interval disables revalidation entirely.
	if s.revalidationInterval <= 0 {
		return nil
	}

	// RULE: Only claims that explicitly opt in (by implementing Revalidatable
	// and reporting a revalidation time) are subject to revalidation. Everything
	// else -- guest/Identity sessions, API tokens, tokens minted before this
	// feature existed -- is exempt and passes through untouched.
	revalidatable, ok := claims.(Revalidatable)

	if !ok {
		return nil
	}

	revalidatedAt, ok := revalidatable.GetRevalidationTime()

	if !ok {
		return nil
	}

	// If the session was verified recently enough, leave it alone.
	if time.Since(revalidatedAt) < s.revalidationInterval {
		return nil
	}

	// The session is stale and opted in, so it MUST revalidate. Recover the
	// stable identifier from the standard "sub" claim so we can re-load the user.
	subject, err := claims.GetSubject()

	if err != nil || subject == "" {
		return derp.Forbidden(location, "Session token cannot be revalidated (missing subject)")
	}

	// RULE: Re-load the user by their stable subject. A "not found" means the
	// user was deleted/revoked; any other error is an infrastructure problem.
	// Both reject (fail closed), but we report them distinctly for diagnostics.
	user := s.userService.New()

	if err := s.userService.LoadBySubject(subject, user); err != nil {

		if derp.IsNotFound(err) {
			return derp.Forbidden(location, "Session is no longer valid", subject)
		}

		return derp.Wrap(err, location, "Unable to revalidate session", subject)
	}

	// Rebuild the claims from the freshly loaded user, picking up any changes to
	// their permissions/groups since the token was minted.
	freshClaims, err := s.userService.Claims(user)

	if err != nil {
		return derp.Wrap(err, location, "Unable to rebuild session claims", subject)
	}

	// A Bearer/header session has no cookie to re-mint, so re-verification is all
	// we can do for it. Cookie sessions get a fresh token, sliding the window.
	if !requestHasAuthCookie(ctx.Request()) {
		return nil
	}

	if err := s.SetCookie(ctx, freshClaims); err != nil {
		return derp.Wrap(err, location, "Unable to re-mint session cookie", subject)
	}

	// Welcome back.
	return nil
}

// requestHasAuthCookie returns TRUE if the request carried its authorization in
// a cookie (which can be re-minted) rather than only an Authorization header.
func requestHasAuthCookie(request *http.Request) bool {
	_, err := request.Cookie(cookieName(request))
	return err == nil
}

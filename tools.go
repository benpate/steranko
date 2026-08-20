package steranko

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// JWTValidMethods returns a jwt.ParserOption that restricts the JWT parser to only accept
// secure encryption methods defined in the golang-jwt package.
// https://pkg.go.dev/github.com/golang-jwt/jwt/v5@v5.2.1#WithValidMethods
func JWTValidMethods() jwt.ParserOption {

	result := make([]string, 0, 3)

	if hs256 := jwt.SigningMethodHS256; hs256 != nil {
		result = append(result, hs256.Name)
	}

	if hs384 := jwt.SigningMethodHS384; hs384 != nil {
		result = append(result, hs384.Name)
	}

	if hs512 := jwt.SigningMethodHS512; hs512 != nil {
		result = append(result, hs512.Name)
	}

	return jwt.WithValidMethods(result)
}

// sleepRandom sleeps for a random amount of time between the
// minimum and maximum values. It draws from crypto/rand so the jitter that
// masks signin timing cannot be predicted by an attacker. If the random draw
// fails (effectively never), it falls back to the maximum delay.
func sleepRandom(lower int, upper int) {
	sleepTime := upper

	if offset, err := rand.Int(rand.Reader, big.NewInt(int64(upper-lower+1))); err == nil {
		sleepTime = lower + int(offset.Int64())
	}

	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
}

// backupCookieMaxAge is how long a masquerade "-backup" cookie survives, in seconds (7 days).
// Security does not rest on this lifetime; it only bounds how long a masquerade can pop back.
const backupCookieMaxAge = 7 * 24 * 60 * 60

// stashBackup copies the request's current session cookie (if present and non-empty) into
// the "-backup" slot, preserving it so a later SignOut can restore it.
func stashBackup(ctx echo.Context) {

	// This one-deep session stack supports masquerade; it is written ONLY by PushCookie.
	// Ordinary sign-in and revalidation use SetCookie, which never stacks.
	request := ctx.Request()
	originalCookie, err := ctx.Cookie(cookieName(request))

	if err != nil {
		return
	}

	// An empty cookie is not a session and must never be stacked as one.
	if originalCookie.Value == "" {
		return
	}

	// RULE: The backup slot holds a live session token, so it MUST carry the same protections
	// as the active session cookie. The attributes are rebuilt here rather than copied from
	// originalCookie, because a cookie read from a REQUEST carries only a Name and a Value --
	// browsers never send Secure/HttpOnly/SameSite/Path back. Copying one yields an unprotected
	// cookie that scripts can read, and whose missing Secure and Path violate the __Host- prefix
	// rules, so the browser drops it and the pop-back silently fails over TLS.
	// #nosec G124 -- Secure tracks the connection because Steranko also serves plain HTTP in
	// development; on TLS isTLS() is true and the __Host- prefix requirement is met.
	ctx.SetCookie(&http.Cookie{
		Name:     originalCookie.Name + "-backup",
		Value:    originalCookie.Value,
		MaxAge:   backupCookieMaxAge,   // 7-day pop-back budget (not the security boundary)
		Path:     "/",                  // Match SetCookie, and satisfy the __Host- prefix
		Secure:   isTLS(request),       // Match SetCookie, and satisfy the __Host- prefix
		HttpOnly: true,                 // Keep the stacked session token away from client-side scripts
		SameSite: http.SameSiteLaxMode, // Match the active session cookie
	})
}

// deleteCookie expires the named cookie immediately.
func deleteCookie(ctx echo.Context, name string) {

	// The attributes match those used when a session cookie is set (Path, Secure, HttpOnly,
	// SameSite) so the browser reliably drops it, including a __Host- prefixed name on TLS.
	// #nosec G124 -- Secure tracks the connection, for the same reason as the session cookie
	// this deletion has to match; a literal `true` would not delete a plain-HTTP cookie.
	ctx.SetCookie(&http.Cookie{
		Name:     name,                    // The cookie to delete
		Value:    "",                      // Erase the value of the cookie
		MaxAge:   -1,                      // Negative Max-Age expires the cookie immediately (0 would omit the attribute)
		Path:     "/",                     // Match the path used when the cookie was set
		Secure:   ctx.IsTLS(),             // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
	})
}

// cookieName returns the cookie name to use for a given request.
// SSL requests use __Host-Authorization, which locks the cookie to this domain
// Non-SSL requests use Authorization, which is not locked to a domain
func cookieName(request *http.Request) string {

	// If this is a secure domain...
	if isTLS(request) {
		// Use a cookie name that can only be set on an SSL connection, and is "domain-locked"
		return "__Host-Authorization"
	}

	return "Authorization"
}

// isTLS returns TRUE if the given http.Request uses an SSL connection
func isTLS(request *http.Request) bool {
	return request.TLS != nil
}

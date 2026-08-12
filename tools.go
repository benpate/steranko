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
	originalCookie, err := ctx.Cookie(cookieName(ctx.Request()))

	if err != nil {
		return
	}

	// Copy the current session cookie, preserving its security attributes.
	backupCookie := copyCookie(originalCookie)

	// An empty cookie is not a session and must never be stacked as one.
	if backupCookie.Value == "" {
		return
	}

	backupCookie.Name += "-backup"
	backupCookie.MaxAge = backupCookieMaxAge // 7-day pop-back budget (not the security boundary)
	backupCookie.Expires = time.Time{}       // rely on Max-Age alone

	ctx.SetCookie(&backupCookie)
}

// deleteCookie expires the named cookie immediately.
func deleteCookie(ctx echo.Context, name string) {

	// The attributes match those used when a session cookie is set (Path, Secure, HttpOnly,
	// SameSite) so the browser reliably drops it, including a __Host- prefixed name on TLS.
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

func copyCookie(original *http.Cookie) http.Cookie {
	return http.Cookie{
		Name:     original.Name,
		Value:    original.Value,
		MaxAge:   original.MaxAge,
		Expires:  original.Expires,
		Domain:   original.Domain,
		Path:     original.Path,
		HttpOnly: original.HttpOnly,
		Secure:   original.Secure,
		SameSite: original.SameSite,
	}
}

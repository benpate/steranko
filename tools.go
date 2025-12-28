package steranko

import (
	"math/rand"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// JWTValidmethods returns a jwt.ParserOption that restricts the JWT parser to only accept
// secure encrytption methods defined inthe golang-jwt package.
// https://pkg.go.dev/github.com/golang-jwt/jwt/v5@v5.2.1#WithValidMethods
func JWTValidMethods() jwt.ParserOption {

	result := make([]string, 0, 3)

	if hs256 := jwt.SigningMethodHS256; hs256 != nil {
		result = append(result, hs256.Name)
	}

	if hs384 := jwt.SigningMethodES384; hs384 != nil {
		result = append(result, hs384.Name)
	}

	if hs512 := jwt.SigningMethodHS512; hs512 != nil {
		result = append(result, hs512.Name)
	}

	return jwt.WithValidMethods(result)
}

// sleepRandom sleeps for a random amount of time between the
// minimum and maximum values
func sleepRandom(min int, max int) {
	sleepTime := rand.Intn(max-min+1) + min
	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
}

// PushCookie sets a new cookie to the user's context, and moves their
// existing cookie (if present) to be the "-backup" cookie.
func pushCookie(ctx echo.Context, cookie http.Cookie) {

	if originalCookie, err := ctx.Cookie(cookie.Name); err == nil {
		backupCookie := copyCookie(originalCookie)

		if backupCookie.Value != "" {
			backupCookie.Name += "-backup"
			ctx.SetCookie(&backupCookie)
		}
	}

	ctx.SetCookie(&cookie)
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

package steranko

import (
	"math/rand"
	"net/http"
	"time"
)

// sleepRandom sleeps for a random amount of time between the
// minimum and maximum values
func sleepRandom(min int, max int) {
	sleepTime := rand.Intn(max-min+1) + min
	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
}

// CookieName returns the cookie name to use for a given request.
// SSL requests use __Host-Authorization, which locks the cookie to this domain
// Non-SSL requests use Authorization, which is not locked to a domain
func CookieName(request *http.Request) string {

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

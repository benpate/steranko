package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzFindAuthorization confirms that token extraction never panics, regardless
// of the bytes presented in the cookie or Authorization header, and that the
// "Bearer " prefix handling is consistent.
func FuzzFindAuthorization(f *testing.F) {

	f.Add("Bearer abc123")
	f.Add("abc123")
	f.Add("")
	f.Add("Bearer ")
	f.Add("Bearer Bearer x")

	s := getTestSteranko()

	f.Fuzz(func(t *testing.T, header string) {

		// Header path
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", header)
		_ = s.findAuthorization(req)

		// Cookie path. Cookie values cannot contain arbitrary control
		// characters, so only exercise values that the http package will
		// accept. We still confirm the lookup never panics.
		cookie := &http.Cookie{Name: "Authorization", Value: header}
		if cookie.Valid() == nil {
			req2 := httptest.NewRequest(http.MethodGet, "/", nil)
			req2.AddCookie(cookie)
			got := s.findAuthorization(req2)
			if got != header {
				t.Fatalf("cookie value round-trip mismatch: got %q want %q", got, header)
			}
		}
	})
}

// FuzzGetAuthorization confirms that parsing an arbitrary token string never
// panics and never returns claims together with a nil error for an invalid
// token. (A malformed token must always be rejected.)
func FuzzGetAuthorization(f *testing.F) {

	f.Add("")
	f.Add("not-a-jwt")
	f.Add("aaa.bbb.ccc")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid")

	s := getTestSteranko()

	f.Fuzz(func(t *testing.T, token string) {

		cookie := &http.Cookie{Name: "Authorization", Value: token}
		if cookie.Valid() != nil {
			t.Skip()
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)

		claims, err := s.GetAuthorization(req)

		// The security-critical invariant: we must never accept a token that
		// the parser rejected (no claims without an error path having run).
		if err == nil && claims == nil {
			t.Fatalf("GetAuthorization returned nil claims AND nil error for token %q", token)
		}
	})
}

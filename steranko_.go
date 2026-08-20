// Package steranko provides embeddable user authentication and authorization
// for Go web applications, including password hashing, validation rules, and
// JWT-based session cookies.
package steranko

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/benpate/derp"
	"github.com/benpate/rosetta/schema"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// defaultRevalidationInterval is how old a token may be before Steranko
// re-verifies it against the UserService on the next request.
const defaultRevalidationInterval = 10 * time.Minute

// Steranko contains all required configuration information for this library.
type Steranko struct {
	userService          UserService     // Service that provides CRUD operations on Users
	signinService        SigninService   // Service that tracks signin successes and failures for users.
	keyService           KeyService      // Service that generates/retrieves encryption keys used in JWT signatures.
	passwordSchema       schema.Schema   // Validating schema to use when setting new passwords.
	passwordRules        []PasswordRule  // PasswordRules are additional validators that are applied to new passwords.
	passwords            PasswordService // PasswordService owns the ordered chain of hashers used to store and verify passwords.
	revalidationInterval time.Duration   // How old a token may be before it is re-verified against the UserService.

	decoyOnce sync.Once // guards the one-time computation of decoyHash
	decoyHash string    // throwaway hash used to equalize the timing of failed signins (see decoyPasswordHash)
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService, keyService KeyService, options ...Option) *Steranko {

	result := Steranko{
		userService:          userService,
		keyService:           keyService,
		signinService:        NilSigninService{},
		passwords:            NewPasswordService(), // BCrypt by default; use hash.Plaintext{} for testing and development
		passwordSchema:       schema.New(schema.String{MinLength: 8, Required: true}),
		revalidationInterval: defaultRevalidationInterval,
	}

	result.WithOptions(options...)

	return &result
}

// WithOptions applies the provided Option functions to this Steranko instance.
//
// This mutates the instance without synchronization and is therefore NOT safe
// to call concurrently with request handling. Apply all options during
// construction (via New, or immediately after) before the Steranko is shared
// across goroutines.
func (s *Steranko) WithOptions(options ...Option) {
	for _, option := range options {
		option(s)
	}
}

// Context returns a new steranko.Context that wraps the provided echo.Context
// and embeds this Steranko instance.
func (s *Steranko) Context(ctx echo.Context) *Context {
	return &Context{
		steranko: s,
		Context:  ctx,
	}
}

// GetAuthorization retrieves the JWT token claims from the request.
func (s *Steranko) GetAuthorization(request *http.Request) (jwt.Claims, error) {

	const location = "steranko.GetAuthorization"

	// Retrieve the cookie/header value from the request and parse it into claims
	claims, err := s.parseToken(s.findAuthorization(request))

	if err != nil {
		return nil, derp.Wrap(err, location, "Error parsing token")
	}

	// Success!
	return claims, nil
}

// parseToken parses and validates a JWT token string, returning its claims. It pins the
// permitted signing methods and rejects any token that is not validly signed and unexpired.
func (s *Steranko) parseToken(tokenString string) (jwt.Claims, error) {

	const location = "steranko.parseToken"

	// Both the active session cookie and a restored "-backup" session parse through here,
	// so the same rigor applies to each. The raw token is kept out of every error detail
	// because it is a bearer credential that must not leak into logs.
	claims := s.userService.NewClaims()
	token, err := jwt.ParseWithClaims(tokenString, claims, s.keyService.FindKey, JWTValidMethods())

	if err != nil {
		return nil, derp.Wrap(err, location, "Error parsing token")
	}

	if !token.Valid {
		return nil, derp.Forbidden(location, "Token is invalid")
	}

	return claims, nil
}

// findAuthorization looks for a JWT token in 1) Cookies and 2) Authorization headers
func (s *Steranko) findAuthorization(request *http.Request) string {

	// First look at cookies
	if cookie, err := request.Cookie(cookieName(request)); err == nil {
		return cookie.Value
	}

	// Otherwise, look at the Authorization header
	if header := request.Header.Get("Authorization"); header != "" {

		// RFC 9110 §11.1 makes the auth scheme case-insensitive, and real clients send
		// "bearer" and extra padding as readily as the canonical "Bearer ". Tolerating the
		// prefix grants nothing on its own -- the token it uncovers still has to survive
		// full signature and expiry checks in parseToken.
		if scheme, token, found := strings.Cut(header, " "); found && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(token)
		}

		// A header with no recognized scheme is treated as a bare token.
		return header
	}

	return ""
}

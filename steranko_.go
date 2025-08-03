package steranko

import (
	"net/http"

	"github.com/benpate/data"
	"github.com/benpate/derp"
	"github.com/benpate/rosetta/schema"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Steranko contains all required configuration information for this library.
type Steranko[T jwt.Claims] struct {
	userService     UserService[T]   // Service that provides CRUD operations on Users
	keyService      KeyService       // Service that generates/retrieves encryption keys used in JWT signatures.
	passwordSchema  schema.Schema    // Validating schema to use when setting new passwords.
	passwordRules   []PasswordRule   // PasswordRules are additional validators that are applied to new passwords.
	passwordHashers []PasswordHasher // PasswordHashers is a list of one-way encryption hashes that stored passwords.
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New[T jwt.Claims](userService UserService[T], keyService KeyService, options ...Option[T]) *Steranko[T] {

	result := Steranko[T]{
		userService:     userService,
		keyService:      keyService,
		passwordHashers: []PasswordHasher{defaultPasswordHasher()}, // hash.Plaintext{},
		passwordSchema:  schema.New(schema.String{MinLength: 8, Required: true}),
	}

	result.WithOptions(options...)

	return &result
}

func (steranko *Steranko[T]) Context(ctx echo.Context, session data.Session) Context[T] {

	return Context[T]{
		session:  session,
		steranko: steranko,
		Context:  ctx,
	}
}

// WithOptions applies the provided Option functions to this Steranko instance.
func (s *Steranko[T]) WithOptions(options ...Option[T]) {
	for _, option := range options {
		option(s)
	}
}

// GetAuthorization retrieves the JWT token claims from the request.
func (s *Steranko[T]) GetAuthorization(request *http.Request, session data.Session) (T, error) {

	const location = "steranko.GetAuthorization"

	// Retrieve the cookie value from the context
	name := cookieName(request)
	cookie, err := request.Cookie(name)

	if err != nil {
		return s.userService.NewClaims(), derp.Wrap(err, location, "Invalid cookie")
	}

	// Parse the tokenString as a JWT token
	claims := s.userService.NewClaims()
	token, err := jwt.ParseWithClaims(cookie.Value, claims, s.keyService.FindKey(session), JWTValidMethods())

	if err != nil {
		return s.userService.NewClaims(), derp.Wrap(err, location, "Error parsing token")
	}

	// Validate the token (date, signature, etc)
	if !token.Valid {
		return s.userService.NewClaims(), derp.ForbiddenError(location, "Token is invalid", cookie, token)
	}

	// Success!
	return claims, nil
}

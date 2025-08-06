package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/rosetta/schema"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// Steranko contains all required configuration information for this library.
type Steranko struct {
	userService     UserService      // Service that provides CRUD operations on Users
	keyService      KeyService       // Service that generates/retrieves encryption keys used in JWT signatures.
	passwordSchema  schema.Schema    // Validating schema to use when setting new passwords.
	passwordRules   []PasswordRule   // PasswordRules are additional validators that are applied to new passwords.
	passwordHashers []PasswordHasher // PasswordHashers is a list of one-way encryption hashes that stored passwords.
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService, keyService KeyService, options ...Option) *Steranko {

	result := Steranko{
		userService:     userService,
		keyService:      keyService,
		passwordHashers: []PasswordHasher{defaultPasswordHasher()}, // hash.Plaintext{},
		passwordSchema:  schema.New(schema.String{MinLength: 8, Required: true}),
	}

	result.WithOptions(options...)

	return &result
}

// WithOptios applies the provided Option functions to this Steranko instance.
func (s *Steranko) WithOptions(options ...Option) {
	for _, option := range options {
		option(s)
	}
}

func (s *Steranko) Context(ctx echo.Context) *Context {
	return &Context{
		steranko: s,
		Context:  ctx,
	}
}

// GetAuthorization retrieves the JWT token claims from the request.
func (s *Steranko) GetAuthorization(request *http.Request) (jwt.Claims, error) {

	const location = "steranko.GetAuthorization"

	// Retrieve the cookie value from the context
	name := cookieName(request)
	cookie, err := request.Cookie(name)

	if err != nil {
		return nil, derp.Wrap(err, location, "Invalid cookie")
	}

	// Parse the tokenString as a JWT token
	claims := s.userService.NewClaims()
	token, err := jwt.ParseWithClaims(cookie.Value, claims, s.keyService.FindKey, JWTValidMethods())

	if err != nil {
		return nil, derp.Wrap(err, location, "Error parsing token")
	}

	// Validate the token (date, signature, etc)
	if !token.Valid {
		return nil, derp.ForbiddenError(location, "Token is invalid", cookie, token)
	}

	// Success!
	return claims, nil
}

package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/rosetta/schema"
	"github.com/golang-jwt/jwt/v5"
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
func (steranko *Steranko) WithOptions(options ...Option) {
	for _, option := range options {
		option(steranko)
	}
}

// GetAuthorization retrieves the JWT token claims from the request.
func (steranko *Steranko) GetAuthorization(request *http.Request) (jwt.Claims, error) {

	// Retrieve the cookie value from the context
	cookieName := cookieName(request)
	cookie, err := request.Cookie(cookieName)

	if err != nil {
		return nil, derp.Wrap(err, "steranko.Context.Claims", "Invalid cookie")
	}

	return steranko.GetAuthorizationFromToken(cookie.Value)
}

// GetAuthorizationFromToken parses a JWT token
func (steranko *Steranko) GetAuthorizationFromToken(tokenString string) (jwt.Claims, error) {

	claims := steranko.userService.NewClaims()

	// Parse it as a JWT token
	token, err := jwt.ParseWithClaims(tokenString, claims, steranko.keyService.FindJWTKey, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))

	if err != nil {
		return nil, derp.Wrap(err, "steranko.Context.Claims", "Error parsing token")
	}

	if !token.Valid {
		return nil, derp.NewForbiddenError("steranko.Context.Claims", "Invalid token")
	}

	return claims, nil
}

/******************************************
 * Utility Methods
 ******************************************/

// PasswordSchema returns the schema.Schema for validating passwords
func (s *Steranko) PasswordSchema() *schema.Schema {
	return &s.passwordSchema
}

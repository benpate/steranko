package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/rosetta/schema"
	"github.com/benpate/steranko/plugin"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/golang-jwt/jwt/v5"
)

// Steranko contains all required configuration information for this library.
type Steranko struct {
	UserService    UserService           // Service that provides CRUD operations on Users
	KeyService     KeyService            // Service that generates/retrieves encryption keys used in JWT signatures.
	Config         Config                // Configuration options for this library
	PasswordHasher plugin.PasswordHasher // PasswordHasher uses a one-way encryption to obscure stored passwords.
	PasswordRules  []plugin.PasswordRule // PasswordRules provide rules for enforcing password complexity

	passwordSchema *schema.Schema
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService, keyService KeyService, config Config) *Steranko {

	result := Steranko{
		UserService: userService,
		KeyService:  keyService,
		Config:      config,

		// PasswordHasher: hash.BCrypt(15),
		PasswordHasher: hash.Plaintext{},
		PasswordRules:  []plugin.PasswordRule{},
	}

	// Parse password rules from config file here

	return &result
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

	claims := steranko.UserService.NewClaims()

	// Parse it as a JWT token
	token, err := jwt.ParseWithClaims(tokenString, claims, steranko.KeyService.FindJWTKey, jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))

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

	if s.passwordSchema == nil {
		s.passwordSchema = &s.Config.PasswordSchema
	}

	return s.passwordSchema
}

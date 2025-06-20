package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// SigninFormPost reads the data from a form post and signs in the user
// using their username/password. If the signin is successful
// it automatically sets the "Authorization" cookie in the user's browser.
// If unsuccessful, an error is returned to the caller.
func (s *Steranko) SigninFormPost(ctx echo.Context) (User, error) {

	const location = "steranko.Signin"

	var txn SigninTransaction

	// Collect values from the request body
	if err := ctx.Bind(&txn); err != nil {
		return nil, derp.Wrap(err, location, "Unable to bind request body", derp.WithCode(http.StatusBadRequest))
	}

	// (short) random sleep to thwart timing attacks
	sleepRandom(500, 1500)

	// Try to authenticate the user
	user := s.userService.New()
	if err := s.authenticate(txn.Username, txn.Password, user); err != nil {
		sleepRandom(1000, 3000) // (medium) random sleep to punish invalid signin attempts
		return nil, derp.ForbiddenError(location, "Invalid username/password.")
	}

	// Try to Sign the User into the server
	if err := s.SigninUser(ctx, user); err != nil {
		return nil, derp.Wrap(err, location, "Error signing in user", user.GetUsername())
	}

	// Success!
	return user, nil
}

// SigninUser writes a cookie to the User's browser that signs them into the server.
func (s *Steranko) SigninUser(ctx echo.Context, user User) error {

	const location = "steranko.SigninUser"

	// Create a new JWT claims object for the user
	claims, err := s.userService.Claims(user)

	if err != nil {
		return derp.Wrap(err, location, "Error generating JSON Web Token claims")
	}

	// Set the claims as a cookie in the User's browser
	if err := s.SetCookie(ctx, claims); err != nil {
		return derp.Wrap(err, location, "Error setting signin cookie")
	}

	// Success.
	return nil
}

// SetCookie writes a Cookie / JWT token to the User's browser using the provided claims.
func (s *Steranko) SetCookie(ctx echo.Context, claims jwt.Claims) error {

	const location = "steranko.SetCookieFromClaims"

	// Create the JWT Token
	token, err := s.CreateJWT(claims)

	if err != nil {
		return derp.Wrap(err, location, "Error creating JSON Web Token")
	}

	// Set the Cookie in the Response
	request := ctx.Request()
	name := cookieName(request)
	secure := isTLS(request)

	// Return the JWT certificate as a cookie
	cookie := http.Cookie{
		Name:     name,
		Value:    token,                // Set the cookie's value
		MaxAge:   2592000,              // Max-Age is 30 DAYS (60s * 60min * 24h * 30d)
		Path:     "/",                  // This allows the cookie on all paths of this site.
		Secure:   secure,               // Set secure cookies if we're on a secure connection
		HttpOnly: true,                 // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteLaxMode, // "Lax" same-site policy allows cookies on GET requests, but prevents cookies from being used by other sites on POST requests.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	}

	// Send the Cookie to the User's browser
	pushCookie(ctx, cookie)

	return nil
}

// CreateJWT generates a new JWT token using the specified claims.
// Sternako writes this JWT token using the HS512 signing method, and
// the signing key that is generated by the embedded KeyService.
func (s *Steranko) CreateJWT(claims jwt.Claims) (string, error) {

	const location = "steranko.CreateJWT"

	// Create a new JWT token with specified claims
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims = claims

	// Get the signing key from the KeyService
	keyID, key, err := s.keyService.GetCurrentKey()

	if err != nil {
		return "", derp.Wrap(err, location, "Error getting key from JSON Web Token")
	}

	token.Header["kid"] = keyID

	// Try to generate encoded token
	result, err := token.SignedString(key)

	if err != nil {
		return result, derp.Wrap(err, location, "Error signing JSON Web Token")
	}

	// Return the encoded token
	return result, nil
}

// ValidatePassword checks a password against all system requirements
func (s *Steranko) ValidatePassword(plaintext string) error {

	const location = "steranko.ValidatePassword"

	// Validate the schema (size, composition, etc)
	if err := s.passwordSchema.Validate(plaintext); err != nil {
		return derp.Wrap(err, location, "Password does not meet requirements")
	}

	// Validate other password rules (complex functions, external services)
	for _, rule := range s.passwordRules {
		if ok, message := rule.ValidatePassword(plaintext); !ok {
			return derp.BadRequestError(location, message)
		}
	}

	// Everything is OK!
	return nil
}

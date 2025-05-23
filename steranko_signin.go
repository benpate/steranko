package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// SignIn implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function if
// you want to extend its functionality.  If the signin is successful
// it automatically sets the "Authorization" cookie in the user's browser.
func (s *Steranko) SignIn(ctx echo.Context) (User, error) {

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
	if err := s.Authenticate(txn.Username, txn.Password, user); err != nil {
		sleepRandom(1000, 3000) // (medium) random sleep to punish invalid signin attempts
		return nil, derp.ForbiddenError(location, "Invalid username/password.")
	}

	// Try to create a JWT token
	certificate, err := s.CreateCertificate(ctx.Request(), user)

	if err != nil {
		return nil, derp.Wrap(err, location, "Error creating JWT certificate")
	}

	// Set the cookie in the user's browser and exit
	ctx.SetCookie(&certificate)
	return user, nil
}

// Authenticate verifies a username/password combination.
func (s *Steranko) Authenticate(username string, password string, user User) error {

	// Try to load the User from the UserService
	if err := s.userService.Load(username, user); err != nil {

		if derp.IsNotFound(err) {
			return derp.UnauthorizedError("steranko.Authenticate", "Unauthorized", username, "user not found")
		}

		return derp.Wrap(err, "steranko.Authenticate", "Error loading User account", username, "database error")
	}

	// If we're here, then we have a matching user account. So, try to authenticate the password
	ok, update := s.ComparePassword(password, user.GetPassword())

	if !ok {
		return derp.UnauthorizedError("steranko.Authenticate", "Unauthorized", username, "invalid password")
	}

	if update {
		// Intentionally ignoring errors updating the password because the user has already
		// authenticated.  If we can't update it now (for some reason) then we'll get it soon.
		if err := s.SetPassword(user, password); err == nil {
			// nolint:errcheck
			s.userService.Save(user, "Password automatically upgraded by Steranko")
		}
	}

	// Success
	return nil
}

func (s *Steranko) PrimaryPasswordHasher() PasswordHasher {
	if len(s.passwordHashers) > 0 {
		return s.passwordHashers[0]
	}

	return defaultPasswordHasher()
}

// ComparePassword uses each
func (s *Steranko) ComparePassword(plaintext string, hashedValue string) (bool, bool) {

	// Try each hashing algorithm in order.
	for index, passwordHasher := range s.passwordHashers {

		// If the password matches, then return success.
		if ok, update := passwordHasher.CompareHashedPassword(hashedValue, plaintext); ok {

			// If we're using a deprecated hashing algorithm, then MUST update
			if index > 0 {
				update = true
			}

			// Yay!
			return ok, update
		}
	}

	// Boo!
	return false, false
}

// CreateCertificate creates a new JWT token for the provided user.
func (s *Steranko) CreateCertificate(request *http.Request, user User) (http.Cookie, error) {

	// Set up a new JWT token
	token, err := s.CreateJWT(user.Claims())

	if err != nil {
		return http.Cookie{}, derp.Wrap(err, "steranko.CreateCertificate", "Error creating JWT token")
	}

	return s.CreateCookie(CookieName(request), token, isTLS(request)), nil
}

func (s *Steranko) CreateCookie(name string, value string, isTLS bool) http.Cookie {

	// Return the JWT certificate as a cookie
	return http.Cookie{
		Name:     name,
		Value:    value,                // Set the cookie's value
		MaxAge:   63072000,             // Max-Age is 2 YEARS (60s * 60min * 24h * 365d * 2y)
		Path:     "/",                  // This allows the cookie on all paths of this site.
		Secure:   isTLS,                // Set secure cookies if we're on a secure connection
		HttpOnly: true,                 // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteLaxMode, // "Lax" same-site policy allows cookies on GET requests, but prevents cookies from being used by other sites on POST requests.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	}
}

// CreateJWT generates a new JWT token using the specified claims.
func (s *Steranko) CreateJWT(claims jwt.Claims) (string, error) {

	const location = "steranko.CreateJWT"

	// Create a new JWT token with specified claims
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims

	// Get the signing key from the KeyService
	keyID, key, err := s.keyService.GetCurrentKey()

	if err != nil {
		return "", derp.Wrap(err, location, "Error getting JWT Key")
	}

	token.Header["kid"] = keyID

	// Try to generate encoded token
	result, err := token.SignedString(key)

	if err != nil {
		return result, derp.Wrap(err, location, "Error Signing JWT Token")
	}

	// Return the encoded token
	return result, nil
}

// ValidatePassword checks a password against all system requirements
func (s *Steranko) ValidatePassword(plaintext string) error {

	const location = "steranko.ValidatePassword"

	// Validate the schema (size, composition, etc)
	if err := s.PasswordSchema().Validate(plaintext); err != nil {
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

// PushCookie sets a new cookie to the user's context, and moves their
// existing cookie to be the "-backup" cookie.
func (s *Steranko) PushCookie(ctx echo.Context, cookie http.Cookie) {

	if originalCookie, err := ctx.Cookie(cookie.Name); err == nil {
		backupCookie := copyCookie(originalCookie)
		backupCookie.Name += "-backup"
		ctx.SetCookie(&backupCookie)
	}

	ctx.SetCookie(&cookie)
}

func defaultPasswordHasher() PasswordHasher {
	return hash.BCrypt(15)
}

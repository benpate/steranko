package steranko

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// SignIn implements the echo.HandlerFunc, and can be used directly
// in your REST API, or can be wrapped by your own custom function if
// you want to extend its functionality.  If the signin is successful
// it automatically sets the "Authorization" cookie in the user's browser.
func (s *Steranko) SignIn(ctx echo.Context) error {

	var txn SigninTransaction

	// Collect values from the request body
	if err := ctx.Bind(&txn); err != nil {
		return derp.NewInternalError("steranko.Signin", "Invalid Request. Please try again later.")
	}

	// Try to authenticate the user
	user := s.UserService.New()
	if err := s.Authenticate(txn.Username, txn.Password, user); err != nil {
		sleepRandom(1000, 3000) // (medium) random sleep to punish invalid signin attempts
		return derp.NewForbiddenError("steranko.Signin", "Invalid username/password.  Please try again.")
	}

	// Try to create a JWT token
	certificate, err := s.CreateCertificate(ctx.Request(), user)

	if err != nil {
		return derp.Wrap(err, "steranko.Signin", "Error creating JWT certificate")
	}

	// Set the cookie in the user's browser and exit
	ctx.SetCookie(&certificate)
	return nil
}

// Authenticate verifies a username/password combination.
func (s *Steranko) Authenticate(username string, password string, user User) error {

	// Try to load the User from the UserService
	if err := s.UserService.Load(username, user); err != nil {

		if derp.NotFound(err) {
			return derp.NewUnauthorizedError("steranko.Authenticate", "Unauthorized", username, "user not found")
		}

		return derp.Wrap(err, "steranko.Authenticate", "Error loading User account", username, "database error")
	}

	// Fall through means that we have a matching user account.

	// Try to authenticate the password
	ok, update := s.PasswordHasher.CompareHashedPassword(password, user.GetPassword())

	if !ok {
		return derp.NewUnauthorizedError("steranko.Authenticate", "Unauthorized", username, "invalid password")
	}

	if update {

		if hashedValue, err := s.PasswordHasher.HashPassword(password); err == nil {
			user.SetPassword(hashedValue)
			_ = s.UserService.Save(user, "Password automatically upgraded by Steranko")
			// Intentionally ignoring errors updating the password because the user has already
			// authenticated.  If we can't update it now (for some reason) then we'll get it soon.
		}
	}

	// Success
	return nil
}

// CreateCertificate creates a new JWT token for the provided user.
func (s *Steranko) CreateCertificate(request *http.Request, user User) (http.Cookie, error) {

	// (short) random sleep to thwart timing attacks
	sleepRandom(500, 1500)

	// Set up a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = user.Claims()

	keyID, key := s.KeyService.NewJWTKey()
	token.Header["kid"] = keyID

	// Generate encoded token and send it as response.
	signedString, err := token.SignedString(key)

	if err != nil {
		return http.Cookie{}, derp.Wrap(err, "steranko.PostSigninTransaction", "Error Signing JWT Token")
	}

	// Return the JWT certificate as a cookie
	return http.Cookie{
		Name:     cookieName(request),
		Value:    signedString,            // Set the cookie's value
		MaxAge:   63072000,                // Max-Age is 2 YEARS (60s * 60min * 24h * 365d * 2y)
		Path:     "/",                     // This allows the cookie on all paths of this site.
		Secure:   isTLS(request),          // Set secure cookies if we're on a secure connection
		HttpOnly: true,                    // Cookies should only be accessible via HTTPS (not client-side scripts)
		SameSite: http.SameSiteStrictMode, // Strict same-site policy prevents cookies from being used by other sites.
		// NOTE: Domain is excluded because it is less restrictive than omitting it. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies]
	}, nil

}

// ValidatePassword checks a password against the requirements in the Config structure.
func (s *Steranko) ValidatePassword(password string) error {

	if err := s.PasswordSchema().Validate(password); err != nil {
		return derp.Wrap(err, "steranko.ValidatePassword", "Password does not meet requirements")
	}

	return nil
}

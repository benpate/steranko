package steranko

import (
	"github.com/benpate/derp"
	"github.com/benpate/steranko/plugin/hash"
)

/******************************************
 * Utility Methods
 ******************************************/

// SetPassword hashes the provided plaintext password and sets it on the User.
func (s *Steranko) SetPassword(user User, plaintext string) error {

	const location = "steranko.SetPassword"

	hashedValue, err := s.getPasswordHasher().HashPassword(plaintext)

	if err != nil {
		return derp.Wrap(err, location, "Error hashing password")
	}

	user.SetPassword(hashedValue)
	return nil
}

/******************************************
 * Helper Methods
 ******************************************/

// Authenticate verifies a username/password combination.
func (s *Steranko) authenticate(username string, password string, user User) error {

	const location = "steranko.Authenticate"

	// Try to load the User from the UserService
	if err := s.userService.Load(username, user); err != nil {

		if derp.IsNotFound(err) {
			return derp.UnauthorizedError(location, "Unauthorized", username, "user not found")
		}

		return derp.Wrap(err, location, "Error loading User account", username, "database error")
	}

	// If we're here, then we have a matching user account. So, try to authenticate the password
	ok, update := s.comparePassword(password, user.GetPassword())

	if !ok {
		return derp.UnauthorizedError(location, "Unauthorized", username, "invalid password")
	}

	if update {
		// Intentionally ignoring errors updating the password because the user has already
		// authenticated.  If we can't update it now (for some reason) then we'll get it soon.
		if err := s.SetPassword(user, password); err == nil {

			if err := s.userService.Save(user, "Password automatically upgraded by Steranko"); err != nil {
				derp.Report(derp.Wrap(err, location, "Error saving User account after password upgrade", user.GetUsername()))
			}
		}
	}

	// Success
	return nil
}

// comparePassword tries to validate the plaintext password and hashedValue using
// each of the password hashers in sequence.  If the password matches THE PRIMARY hasher,
// then this returns TRUE, FALSE.  If the password matches any of THE BACKUP hashers,
// then this returns TRUE, TRUE.  If the password does not match any of the hashers
// then this returns FALSE, FALSE.
func (s *Steranko) comparePassword(plaintext string, hashedValue string) (matches bool, update bool) {

	// Try each hashing algorithm in order.
	for index, passwordHasher := range s.passwordHashers {

		// If the password matches, then return success.
		if matches, update := passwordHasher.CompareHashedPassword(hashedValue, plaintext); matches {

			// If we're using a deprecated hashing algorithm, then MUST update
			if index > 0 {
				update = true
			}

			// Yay!
			return matches, update
		}
	}

	// Boo!
	return false, false
}

// getPasswordHasher returns the "primary" PasswordHasher, which is
// the first one in the list. If no PasswordHashers have been configured,
// it returns the default PasswordHasher.
func (s *Steranko) getPasswordHasher() PasswordHasher {
	if len(s.passwordHashers) > 0 {
		return s.passwordHashers[0]
	}

	return defaultPasswordHasher()
}

// The defaultPasswordHasher is a simple BCrypt hasher with a cost of 15.
func defaultPasswordHasher() PasswordHasher {
	return hash.BCrypt(15)
}

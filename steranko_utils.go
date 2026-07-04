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
	return s.passwords.SetPassword(user, plaintext)
}

// ComparePassword tries to validate the plaintext password and hashedValue using
// each of the configured password hashers.  See PasswordService.ComparePassword
// for the full contract.
func (s *Steranko) ComparePassword(plaintext string, hashedValue string) (bool, bool) {
	return s.passwords.ComparePassword(plaintext, hashedValue)
}

// Passwords returns the PasswordService that owns this Steranko's hasher chain,
// for callers that need to hash or compare passwords outside of a signin flow.
func (s *Steranko) Passwords() PasswordService {
	return s.passwords
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

			// Compare against a decoy hash so that a missing account takes the
			// same time as a real password check. This prevents an attacker
			// from enumerating valid usernames by measuring response times.
			s.ComparePassword(password, s.decoyPasswordHash())

			return derp.Unauthorized(location, "Unauthorized", username, "user not found")
		}

		return derp.Wrap(err, location, "Unable to load User account", username, "database error")
	}

	// If we're here, then we have a matching user account. So, try to authenticate the password
	ok, update := s.ComparePassword(password, user.GetHashedPassword())

	if !ok {
		return derp.Unauthorized(location, "Unauthorized", username, "invalid password")
	}

	if update {
		// Intentionally ignoring errors updating the password because the user has already
		// authenticated.  If we can't update it now (for some reason) then we'll get it soon.
		if err := s.SetPassword(user, password); err == nil {

			if err := s.userService.Save(user, "Password automatically upgraded by Steranko"); err != nil {
				derp.Report(derp.Wrap(err, location, "Unable to save User account after password upgrade", user.GetUsername()))
			}
		}
	}

	// Success
	return nil
}

// decoyPasswordHash returns a throwaway hash, computed once with the primary
// hasher and cached, that is used to keep the timing of a failed (user-not-found)
// signin indistinguishable from a real password comparison. Using the primary
// hasher ensures the decoy comparison costs the same as a genuine one.
func (s *Steranko) decoyPasswordHash() string {

	s.decoyOnce.Do(func() {

		const decoyPlaintext = "steranko-decoy-password" // value is irrelevant; we only need a valid hash

		// Prefer the configured primary hasher so the decoy comparison costs the same as a real one.
		if hashed, err := s.passwords.HashPassword(decoyPlaintext); err == nil {
			s.decoyHash = hashed
			return
		}

		// Fall back to the default hasher so a failed primary hasher cannot
		// leave us with an empty decoy (which would skip the timing-equalizing
		// comparison and re-open the username-enumeration side-channel).
		if hashed, err := defaultPasswordHasher().HashPassword(decoyPlaintext); err == nil {
			s.decoyHash = hashed
		}
	})

	return s.decoyHash
}

// The defaultPasswordHasher is a simple BCrypt hasher.  Cost 12 keeps a single
// hash near ~200ms: slow enough to resist offline cracking (OWASP recommends
// >= 10), fast enough that signin latency and the CPU cost of a failed-signin
// flood stay reasonable.
func defaultPasswordHasher() PasswordHasher {
	return hash.BCrypt(12)
}

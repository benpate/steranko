package steranko

import (
	"github.com/benpate/derp"
)

// PasswordService owns an ordered chain of PasswordHashers, and every rule about
// how that chain is used: the first hasher is the "primary", which creates all new
// password hashes; the remaining hashers only verify legacy values, which are
// flagged for transparent re-hashing after a successful comparison.
//
// PasswordService is a pure value type — no database, no user service — so that
// applications can hash and compare passwords without constructing a full
// Steranko instance.
type PasswordService struct {
	hashers []PasswordHasher
}

// NewPasswordService returns a fully initialized PasswordService.  If no hashers
// are provided, the default PasswordHasher (BCrypt) is used.
func NewPasswordService(hashers ...PasswordHasher) PasswordService {

	if len(hashers) == 0 {
		hashers = []PasswordHasher{defaultPasswordHasher()}
	}

	return PasswordService{
		hashers: hashers,
	}
}

// primary returns the hasher that creates new password hashes.  This is the only
// place where "the first hasher in the chain is the primary" is encoded.  A
// zero-value PasswordService falls back to the default hasher so that hashing
// can never silently degrade (or panic) on a misconfigured instance.
func (service PasswordService) primary() PasswordHasher {

	if len(service.hashers) > 0 {
		return service.hashers[0]
	}

	return defaultPasswordHasher()
}

// HashPassword hashes a plaintext password with the primary hasher, returning a
// value that is safe to store.
func (service PasswordService) HashPassword(plaintext string) (string, error) {

	const location = "steranko.PasswordService.HashPassword"

	hashedValue, err := service.primary().HashPassword(plaintext)

	if err != nil {
		return "", derp.Wrap(err, location, "Error hashing password")
	}

	return hashedValue, nil
}

// SetPassword hashes a plaintext password with the primary hasher, then stores the
// result on the User.  This is the only way to set a password from plaintext;
// User.SetHashedPassword must never receive an unhashed value.
func (service PasswordService) SetPassword(user User, plaintext string) error {

	const location = "steranko.PasswordService.SetPassword"

	hashedValue, err := service.HashPassword(plaintext)

	if err != nil {
		return derp.Wrap(err, location, "Error setting password")
	}

	user.SetHashedPassword(hashedValue)
	return nil
}

// ComparePassword tries to validate the plaintext password and hashedValue using
// each of the password hashers in sequence.  If the password matches THE PRIMARY
// hasher, then this returns TRUE, FALSE.  If the password matches any of THE BACKUP
// hashers, then this returns TRUE, TRUE — meaning the stored value must be re-hashed
// with the primary.  If the password does not match any of the hashers, then this
// returns FALSE, FALSE.
func (service PasswordService) ComparePassword(plaintext string, hashedValue string) (bool, bool) {

	// Try each hashing algorithm in order.
	for index, passwordHasher := range service.hashers {

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

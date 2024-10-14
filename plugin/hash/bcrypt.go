package hash

import (
	"github.com/benpate/derp"
	"golang.org/x/crypto/bcrypt"
)

// BCrypt is the default password encryption scheme for Steranko.  The integer value represents the
// complexity cost of the algorithm.
type BCrypt int

// ID returns a unique identifier for this plugin.
func (bc BCrypt) ID() string {
	return "BCrypt"
}

// HashPassword returns a hashed value for the password.
func (bc BCrypt) HashPassword(plaintext string) (hashedValue string, error error) {

	// Trim password to 72 characters, which is the maximum length that bcrypt will accept.
	// https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword
	plaintext = maxlength(plaintext, 72)

	result, err := bcrypt.GenerateFromPassword([]byte(plaintext), int(bc))

	if err != nil {
		return "", derp.Wrap(err, "steranko.plugin.hash.HashPassword", "Error hashing plaintext", derp.WithInternalError())
	}

	return string(result), nil
}

// CompareHashedPassword checks that a hashedValue value matches the plaintext password.
func (bc BCrypt) CompareHashedPassword(hashedValue string, plaintext string) (OK bool, rehash bool) {

	// Trim password to 72 characters, which is the maximum length that bcrypt will accept.
	// https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword
	plaintext = maxlength(plaintext, 72)

	// Try to validate the password.  If it cannot be matched, then return failure.
	if err := bcrypt.CompareHashAndPassword([]byte(hashedValue), []byte(plaintext)); err != nil {
		// FALSE, FALSE means that the password is not OK.
		return false, false
	}

	// Try to compute the password cost.
	cost, err := bcrypt.Cost([]byte(hashedValue))

	if err != nil {
		// Silently report this error because we don't want to interrupt the application flow.
		derp.Report(derp.Wrap(err, "steranko.plugin.hash.CompareHashedPassword", "Error generating password cost", derp.WithInternalError()))
	}

	if cost < int(bc) {
		// TRUE, TRUE means that the password is OK, but needs to be re-hashed
		return true, true
	}

	// TRUE, FALSE means that the password is OK, and doesn't need to be re-hashed
	return true, false
}

func maxlength(value string, max int) string {

	if len(value) > max {
		return value[:max]
	}

	return value
}

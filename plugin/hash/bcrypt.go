// Package hash provides password hashing algorithm plugins for Steranko.
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
func (bc BCrypt) HashPassword(plaintext string) (hashedValue string, err error) {

	const location = "steranko.plugin.hash.BCrypt.HashPassword"

	// Trim password to 72 characters, which is the maximum length that bcrypt will accept.
	// https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword
	plaintext = maxlength(plaintext, 72)

	result, err := bcrypt.GenerateFromPassword([]byte(plaintext), int(bc))

	if err != nil {
		return "", derp.Wrap(err, location, "Error hashing plaintext", derp.WithInternalError())
	}

	return string(result), nil
}

// MaximumCost is the highest bcrypt cost this package will verify a stored password against,
// unless the hasher is itself configured for more (see maximumCost). The work factor is
// exponential and is read out of the hash itself, so the stored cost alone decides how long a
// single comparison runs. Measured on a 2025 laptop: cost 12 (the default) ~0.2s, cost 15
// ~1.6s, cost 17 ~6.5s, cost 20 ~52s, cost 24 ~15 minutes, cost 31 in days.
//
// 15 leaves eight-fold headroom over the default for a deliberate cost increase, while capping
// what one crafted hash can cost the server at seconds instead of hours.
const MaximumCost = 15

// CompareHashedPassword checks that a hashedValue value matches the plaintext password.
func (bc BCrypt) CompareHashedPassword(hashedValue string, plaintext string) (OK bool, rehash bool) {

	const location = "steranko.plugin.hash.BCrypt.CompareHashedPassword"

	// RULE: Read the stored cost BEFORE running a comparison at that cost. Parsing it costs
	// ~50 microseconds and tells us whether honoring it would take minutes. This runs on an
	// unauthenticated signin attempt, so an unbounded work factor here is a denial of service.
	cost, err := bcrypt.Cost([]byte(hashedValue))

	if err != nil {
		// A value that is not a bcrypt hash cannot match one.
		return false, false
	}

	// RULE: Refuse a cost the server cannot afford. Treating it as a non-match keeps this
	// function's FALSE, FALSE contract rather than inventing a failure mode for callers to
	// handle, and no signin could have completed at that cost regardless.
	if affordable := bc.maximumCost(); cost > affordable {
		derp.Report(derp.Internal(location, "Refusing to verify a password hash that declares an unaffordable bcrypt cost", cost, affordable))
		return false, false
	}

	// Trim password to 72 characters, which is the maximum length that bcrypt will accept.
	// https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword
	plaintext = maxlength(plaintext, 72)

	// Try to validate the password.  If it cannot be matched, then return failure.
	if err := bcrypt.CompareHashAndPassword([]byte(hashedValue), []byte(plaintext)); err != nil {
		// FALSE, FALSE means that the password is not OK.
		return false, false
	}

	if cost != int(bc) {
		// TRUE, TRUE means that the password is OK, but is stored at a different
		// cost than currently configured, so it needs to be re-hashed.  This
		// converges storage on the configured cost in BOTH directions: it
		// upgrades weaker hashes after the cost is raised, and it retires
		// more-expensive legacy hashes (with their slower comparisons) after
		// the cost is lowered.
		return true, true
	}

	// TRUE, FALSE means that the password is OK, and doesn't need to be re-hashed
	return true, false
}

// maximumCost returns the highest stored cost this hasher will verify: MaximumCost, or the
// configured cost when that is higher. An application that deliberately chose an expensive cost
// has accepted the price of its own hashes, and must never be locked out of them by the ceiling.
func (bc BCrypt) maximumCost() int {
	return max(int(bc), MaximumCost)
}

// maxlength truncates a string to at most limit BYTES, which is the unit bcrypt
// counts in. It may split a multi-byte rune; that is acceptable here because the
// result is only ever fed to bcrypt, never displayed or stored as text.
func maxlength(value string, limit int) string {

	if len(value) > limit {
		return value[:limit]
	}

	return value
}

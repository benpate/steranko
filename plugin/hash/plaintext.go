package hash

import "crypto/subtle"

// Plaintext is an awful password encryption scheme that should NEVER be used outside of initial development.
type Plaintext struct{}

// ID returns a unique identifier for this plugin.
func (p Plaintext) ID() string {
	return "Plaintext"
}

// HashPassword returns a hashed value for the password.
func (p Plaintext) HashPassword(password string) (string, error) {
	return password, nil
}

// CompareHashedPassword checks that a ciphertext value matches the plaintext password.
func (p Plaintext) CompareHashedPassword(ciphertext string, plaintext string) (OK bool, rehash bool) {
	// Constant-time comparison avoids leaking how many leading characters match.
	match := subtle.ConstantTimeCompare([]byte(ciphertext), []byte(plaintext)) == 1

	// Rehash is unconditionally TRUE so that a stored plaintext "hash" is replaced the moment
	// a real hasher is put in front of it. When Plaintext is itself the primary hasher, this
	// costs a redundant re-hash and save on every signin -- acceptable, because Plaintext is
	// for development only.
	return match, true
}

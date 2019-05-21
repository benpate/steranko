package hash

import "github.com/benpate/derp"

// Plaintext is an awful password encryption scheme that should NEVER be used outside of initial development.
type Plaintext struct{}

// ID returns a unique identifier for this plugin.
func (p Plaintext) ID() string {
	return "Plaintext"
}

// HashPassword returns a hashed value for the password.
func (p Plaintext) HashPassword(password string) (string, *derp.Error) {
	return password, nil
}

// CompareHashedPassword checks that a ciphertext value matches the plaintext password.
func (p Plaintext) CompareHashedPassword(ciphertext string, plaintext string) (OK bool, rehash bool) {
	return true, false
}

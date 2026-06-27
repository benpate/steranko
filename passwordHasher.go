package steranko

// PasswordHasher handles all encryption functions for passwords.
type PasswordHasher interface {

	// ID returns a string that uniquely identifies this plugin.
	ID() string

	// HashPassword returns a hashed value that can be safely stored in a database.
	HashPassword(plaintext string) (ciphertext string, err error)

	// CompareHashedPassword checks that a plaintext password matches a stored ciphertext value.
	// OK returns TRUE if the values match.  Rehash returns TRUE if the hashing criteria has
	// changed and the password should be re-hashed and stored in its place.
	CompareHashedPassword(ciphertext string, plaintext string) (OK bool, Rehash bool)
}

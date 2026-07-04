package steranko

// User interface wraps all of the functions that Steranko needs to authorize a user of the system.
// This is done so that Steranko can be retrofitted on to your existing data objects.  Just implement
// this interface, and a CRUD service, and you're all set.
//
// The "HashedPassword" accessors store and return the password AS HASHED by a PasswordHasher.
// Implementations must be dumb getters/setters: they must never receive a plaintext password.
// To set a password from plaintext, call Steranko.SetPassword, which hashes first.
type User interface {
	GetUsername() string       // Returns the username of the User
	GetHashedPassword() string // Returns the hashed password of the User

	SetUsername(username string)          // Sets the username of the User
	SetHashedPassword(hashedValue string) // Sets the (already hashed) password of the User
}

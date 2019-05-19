package steranko

// User represents a single record (stored in the data.Datastore) that will allow
// access to this system
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}


// IsValid returns TRUE if the provided plaintext password matches
// the hashed value in this record.  The `reset` return value is TRUE
// if the password strength has been updated, and the record should be
// re-saved to the database.
func (user *User) IsValid(password string) (OK bool, reset bool) {

	return false, false
}

// IsPwned returns TRUE
func IsPwned(password string) bool {
	return false
}
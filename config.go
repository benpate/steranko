package steranko

type Config struct {
	Token          string // Where to store authentication tokens.  Valid values are HEADER (default value) or COOKIE
	PasswordSchema string // JSON-encoded schema for password validation rules.
}

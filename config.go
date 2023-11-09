package steranko

import "github.com/benpate/rosetta/schema"

type Config struct {
	PasswordSchema schema.Schema `json:"passwordSchema"` // JSON-encoded schema for password validation rules.
}

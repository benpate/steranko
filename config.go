package steranko

import "github.com/benpate/rosetta/schema"

// Config holds the file-loadable settings for a Steranko instance.
type Config struct {
	PasswordSchema schema.Schema `json:"passwordSchema"` // JSON-encoded schema for password validation rules.
}

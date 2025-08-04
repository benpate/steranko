package steranko

import (
	"github.com/golang-jwt/jwt/v5"
)

// KeyService is an interface that the calling application must implement
// in order to use Steranko.  The KeyService manages the encryption keys
// that sign and verify JWT tokens.
type KeyService interface {

	// GetCurrentKey returns the current JWT key in use by the server
	GetCurrentKey() (string, any, error)

	// FindKey returns the key associated with the given JWT token.
	FindKey(*jwt.Token) (any, error)
}

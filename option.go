package steranko

import (
	"github.com/benpate/rosetta/schema"
	"github.com/golang-jwt/jwt/v5"
)

type Option[T jwt.Claims] func(*Steranko[T])

// WithPasswordSchema sets the provided schema.Schema as the validation
// function when setting new passwords.  Default is (minimum length: 8 characters)
func WithPasswordSchema[T jwt.Claims](passwordSchema schema.Schema) Option[T] {
	return func(s *Steranko[T]) {
		s.passwordSchema = passwordSchema
	}
}

// WithPasswordRules appends the provided password rules the the
// list used when setting new passwords.
func WithPasswordRules[T jwt.Claims](passwordRules ...PasswordRule) Option[T] {
	return func(s *Steranko[T]) {
		s.passwordRules = append(s.passwordRules, passwordRules...)
	}
}

// WithPasswordHashers sets the hashing algorithm(s) to use when
// setting/validating passwords.  The first hasher in the list is
// used to create new passwords.  All subsequent hashers are "deprecated"
// and will be upgrated to the primary algorithm the next time the user
// signs in.
func WithPasswordHasher[T jwt.Claims](hashers ...PasswordHasher) Option[T] {
	return func(s *Steranko[T]) {
		s.passwordHashers = hashers
	}
}

// WithConfigFile loads the values from a configuration file into
// this Steranko instance.
func WithConfigFile[T jwt.Claims](config Config) Option[T] {
	return func(s *Steranko[T]) {
		if config.PasswordSchema.Element != nil {
			s.passwordSchema = config.PasswordSchema
		}
	}
}

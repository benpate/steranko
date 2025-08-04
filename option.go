package steranko

import (
	"github.com/benpate/rosetta/schema"
)

type Option func(*Steranko)

// WithPasswordSchema sets the provided schema.Schema as the validation
// function when setting new passwords.  Default is (minimum length: 8 characters)
func WithPasswordSchema(passwordSchema schema.Schema) Option {
	return func(s *Steranko) {
		s.passwordSchema = passwordSchema
	}
}

// WithPasswordRules appends the provided password rules the the
// list used when setting new passwords.
func WithPasswordRules(passwordRules ...PasswordRule) Option {
	return func(s *Steranko) {
		s.passwordRules = append(s.passwordRules, passwordRules...)
	}
}

// WithPasswordHashers sets the hashing algorithm(s) to use when
// setting/validating passwords.  The first hasher in the list is
// used to create new passwords.  All subsequent hashers are "deprecated"
// and will be upgrated to the primary algorithm the next time the user
// signs in.
func WithPasswordHasher(hashers ...PasswordHasher) Option {
	return func(s *Steranko) {
		s.passwordHashers = hashers
	}
}

// WithConfigFile loads the values from a configuration file into
// this Steranko instance.
func WithConfigFile(config Config) Option {
	return func(s *Steranko) {
		if config.PasswordSchema.Element != nil {
			s.passwordSchema = config.PasswordSchema
		}
	}
}

package steranko

import (
	"github.com/benpate/steranko/plugin"
	"github.com/benpate/steranko/plugin/hash"
)

// Steranko contains all required configuration information for this library.
type Steranko struct {
	UserService    UserService           // Service that provides CRUD operations on Users
	Config         Config                // Configuration options for this library
	PasswordHasher plugin.PasswordHasher // PasswordHasher uses a one-way encryption to obscure stored passwords.
	PasswordRules  []plugin.PasswordRule // PasswordRules provide rules for enforcing password complexity
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService, config Config) *Steranko {

	result := Steranko{
		UserService: userService,
		Config:      config,
		// PasswordHasher: hash.BCrypt(15),
		PasswordHasher: hash.Plaintext{},
		PasswordRules:  []plugin.PasswordRule{},
	}

	// Parse password rules from config file here

	return &result
}

// UsePasswordRule adds a plugin to the Steranko instance, so that it will be called at the appropriate points in the workflow.
// This should only be called during system startup and initialization.
func (s *Steranko) UsePasswordRule(rule plugin.PasswordRule) {

	for index, oldRule := range s.PasswordRules {

		if rule.ID() == oldRule.ID() {
			s.PasswordRules[index] = rule
			return
		}
	}

	s.PasswordRules = append(s.PasswordRules, rule)
}

// RemovePlugin removes a plugin (by name) from the Steranko instance, so that it will no longer be used.
// It returns TRUE if the plugin name was found in the current list.  Otherwise, FALSE,
// This should only be called during system startup and initialization.
func (s *Steranko) RemovePlugin(name string) {

	for index, rule := range s.PasswordRules {

		if rule.ID() == name {
			s.PasswordRules = append(s.PasswordRules[:index], s.PasswordRules[index+1:]...)
			return
		}
	}
}

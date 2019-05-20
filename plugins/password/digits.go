package password

import (
	"fmt"
)

// MinDigits is a Plugin that validates the minimum length of passwords
type MinDigits int

// Name returns the name of this plugin, and is required for this object to implement the "Plugin" interface
func (rule MinDigits) Name() string {
	return "MinDigits"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinDigits) PasswordRuleDescription(language string) string {

	return fmt.Sprint("Must be at least %i characters long.")
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinDigits) ValidatePassword(password string, language string) (OK bool, message string) {

	if CountDigits(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprint("Password must be at least %i characters long", rule)
}

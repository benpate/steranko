package rule

import (
	"fmt"
)

// MinLowercase is a Plugin that validates the minimum length of passwords
type MinLowercase int

// Name returns the name of this plugin, and is required for this object to implement the "Plugin" interface
func (rule MinLowercase) Name() string {
	return "MinLowercase"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinLowercase) PasswordRuleDescription(language string) string {

	return fmt.Sprint("Must be at least %i characters long.")
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinLowercase) ValidatePassword(password string, language string) (OK bool, message string) {

	if CountLowercase(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprint("Password must be at least %i characters long", rule)
}

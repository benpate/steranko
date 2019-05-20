package password

import "fmt"

// MinLength is a Plugin that validates the minimum length of passwords
type MinLength int

// Name returns the name of this plugin, and is required for this object to implement the "Plugin" interface
func (rule MinLength) Name() string {
	return "MinLength"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinLength) PasswordRuleDescription(language string) string {

	return fmt.Sprintf("Must be at least %d characters long", rule)
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinLength) ValidatePassword(password string, language string) (OK bool, message string) {

	if len(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must be at least %d characters long", rule)
}

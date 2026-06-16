package rule

import (
	"fmt"
)

// MinDigits is a Plugin that validates the minimum number of digits in a password.
type MinDigits int

// ID returns a string that uniquely identifies this plugin.
func (rule MinDigits) ID() string {
	return "MinDigits"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinDigits) PasswordRuleDescription(language string) string {

	return fmt.Sprintf("Must contain at least %d digits", int(rule))
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinDigits) ValidatePassword(password string) (OK bool, message string) {

	if CountDigits(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must contain at least %d digits", int(rule))
}

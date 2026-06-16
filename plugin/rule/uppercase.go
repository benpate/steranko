package rule

import (
	"fmt"
)

// MinUppercase is a Plugin that validates the minimum number of uppercase letters in a password.
type MinUppercase int

// ID returns a string that uniquely identifies this plugin.
func (rule MinUppercase) ID() string {
	return "MinUppercase"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinUppercase) PasswordRuleDescription(language string) string {

	return fmt.Sprintf("Must contain at least %d uppercase letters", int(rule))
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinUppercase) ValidatePassword(password string) (OK bool, message string) {

	if CountUppercase(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must contain at least %d uppercase letters", int(rule))
}

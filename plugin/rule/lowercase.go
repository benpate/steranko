package rule

import (
	"fmt"
)

// MinLowercase is a Plugin that validates the minimum number of lowercase letters in a password.
type MinLowercase int

// ID returns a string that uniquely identifies this plugin.
func (rule MinLowercase) ID() string {
	return "MinLowercase"
}

// PasswordRuleDescription returns a human-friendly description of the password rule.
func (rule MinLowercase) PasswordRuleDescription() string {

	return fmt.Sprintf("Must contain at least %d lowercase letters", int(rule))
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinLowercase) ValidatePassword(password string) (OK bool, message string) {

	if CountLowercase(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must contain at least %d lowercase letters", int(rule))
}

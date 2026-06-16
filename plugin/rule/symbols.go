package rule

import "fmt"

// MinSymbols is a Plugin that validates the minimum number of symbols in a password.
type MinSymbols int

// ID returns a string that uniquely identifies this plugin.
func (rule MinSymbols) ID() string {
	return "MinSymbols"
}

// PasswordRuleDescription returns a human-friendly description of the password rule.
func (rule MinSymbols) PasswordRuleDescription() string {

	return fmt.Sprintf("Must contain at least %d symbols", int(rule))
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinSymbols) ValidatePassword(password string) (OK bool, message string) {

	if CountSymbols(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must contain at least %d symbols", int(rule))
}

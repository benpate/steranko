package rule

import "fmt"

// MinSymbols is a Plugin that validates the minimum length of passwords
type MinSymbols int

// ID returns a string that uniquely identifies this plugin.
func (rule MinSymbols) ID() string {
	return "MinSymbols"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinSymbols) PasswordRuleDescription(language string) string {

	return fmt.Sprint("Must be at least %i characters long.", rule)
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinSymbols) ValidatePassword(password string) (OK bool, message string) {

	if CountSymbols(password) >= int(rule) {
		return true, ""
	}

	return false, fmt.Sprint("Password must be at least %i characters long", rule)
}

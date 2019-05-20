package password

import "fmt"

// MinLength is a Plugin that validates the minimum length of passwords
type MinLength int

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (minLength MinLength) PasswordRuleDescription(language string) string {

	return fmt.Sprintf("Must be at least %d characters long", minLength)
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaing the problem.
func (minLength MinLength) ValidatePassword(password string, language string) (OK bool, message string) {

	if len(password) >= int(minLength) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must be at least %d characters long", minLength)
}

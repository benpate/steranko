package rule

import (
	"fmt"
	"math"
)

// MinComplexity is a plugin that calculates the possible combinations of passwords, and validates against a minimum threshold.
type MinComplexity int64

// ID returns a string that uniquely identifies this plugin.
func (rule MinComplexity) ID() string {
	return "MinComplexity"
}

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (rule MinComplexity) PasswordRuleDescription(language string) string {
	return fmt.Sprintf("Must allow at least %d possible combinations", int64(rule))
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (rule MinComplexity) ValidatePassword(password string) (OK bool, message string) {

	if Combinations(password) >= int64(rule) {
		return true, ""
	}

	return false, fmt.Sprintf("Password must allow at least %d possible combinations", int64(rule))
}

// Combinations estimates the size of the keyspace for a password: the size of
// the character pool implied by the character classes it uses, raised to the
// length of the password. The result saturates at math.MaxInt64.
func Combinations(password string) int64 {

	pool := int64(0)

	if CountLowercase(password) > 0 {
		pool += 26
	}

	if CountUppercase(password) > 0 {
		pool += 26
	}

	if CountDigits(password) > 0 {
		pool += 10
	}

	if CountSymbols(password) > 0 {
		pool += 32 // size of the symbol set recognized by symbolRegex
	}

	// A password with no recognized character classes has no keyspace.
	if pool == 0 {
		return 0
	}

	// Raise the pool size to the password length, saturating on overflow.
	result := int64(1)
	for range password {
		if result > math.MaxInt64/pool {
			return math.MaxInt64
		}
		result *= pool
	}

	return result
}

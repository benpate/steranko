package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinDigits_Name(t *testing.T) {
	assert.Equal(t, "MinDigits", MinDigits(3).Name())
}

// TestMinDigits_ValidatePassword exercises the (correct) counting logic: a
// password passes only when it contains at least `rule` digits.
func TestMinDigits_ValidatePassword(t *testing.T) {

	rule := MinDigits(2)

	// run asserts the OK result for a given password.
	run := func(password string, expectedOK bool) {
		ok, message := rule.ValidatePassword(password, "en")
		assert.Equal(t, expectedOK, ok, "password %q", password)
		if expectedOK {
			assert.Equal(t, "", message)
		} else {
			assert.NotEmpty(t, message)
		}
	}

	run("", false)         // 0 digits
	run("abc", false)      // 0 digits
	run("a1b", false)      // 1 digit
	run("a1b2", true)      // 2 digits
	run("12345", true)     // 5 digits
	run("p4ssw0rd9", true) // 3 digits

	// A rule of zero accepts any password.
	zero := MinDigits(0)
	ok, message := zero.ValidatePassword("no-digits-here", "en")
	assert.True(t, ok)
	assert.Equal(t, "", message)
}

// TestMinDigits_Messages documents the CURRENT (buggy) human-readable strings.
// They use fmt.Sprint with a non-functional "%i" verb, so the rule count is
// appended rather than interpolated. These assertions exist to flag the change
// when the formatting bug is fixed.
func TestMinDigits_Messages(t *testing.T) {

	assert.Equal(t, "Must be at least %i characters long.3", MinDigits(3).PasswordRuleDescription("en"))

	_, message := MinDigits(3).ValidatePassword("", "en")
	assert.Equal(t, "Password must be at least %i characters long3", message)
}

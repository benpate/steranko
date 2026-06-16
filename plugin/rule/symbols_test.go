package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinSymbols_ID(t *testing.T) {
	assert.Equal(t, "MinSymbols", MinSymbols(2).ID())
}

func TestMinSymbols_ValidatePassword(t *testing.T) {

	rule := MinSymbols(2)

	run := func(password string, expectedOK bool) {
		ok, message := rule.ValidatePassword(password)
		assert.Equal(t, expectedOK, ok, "password %q", password)
		if expectedOK {
			assert.Equal(t, "", message)
		} else {
			assert.NotEmpty(t, message)
		}
	}

	run("", false)          // 0 symbols
	run("abcDEF123", false) // 0 symbols
	run("a!b", false)       // 1 symbol
	run("a!b@", true)       // 2 symbols
	run("!@#$", true)       // 4 symbols

	// A rule of zero accepts any password.
	zero := MinSymbols(0)
	ok, message := zero.ValidatePassword("no-symbols")
	assert.True(t, ok)
	assert.Equal(t, "", message)
}

// TestMinSymbols_Messages documents the CURRENT (buggy) "%i" output. See the
// note in digits_test.go.
func TestMinSymbols_Messages(t *testing.T) {

	assert.Equal(t, "Must be at least %i characters long.2", MinSymbols(2).PasswordRuleDescription("en"))

	_, message := MinSymbols(2).ValidatePassword("abc")
	assert.Equal(t, "Password must be at least %i characters long2", message)
}

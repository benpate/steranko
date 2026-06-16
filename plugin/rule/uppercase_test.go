package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinUppercase_ID(t *testing.T) {
	assert.Equal(t, "MinUppercase", MinUppercase(3).ID())
}

func TestMinUppercase_ValidatePassword(t *testing.T) {

	rule := MinUppercase(3)

	run := func(password string, expectedOK bool) {
		ok, message := rule.ValidatePassword(password)
		assert.Equal(t, expectedOK, ok, "password %q", password)
		if expectedOK {
			assert.Equal(t, "", message)
		} else {
			assert.NotEmpty(t, message)
		}
	}

	run("", false)        // 0 uppercase
	run("abc123", false)  // 0 uppercase
	run("Ab", false)      // 1 uppercase
	run("ABc", false)     // 2 uppercase
	run("ABC", true)      // 3 uppercase
	run("AbCdEf", true)   // 3 uppercase (A,C,E)
	run("PASSWORD", true) // 8 uppercase
}

func TestMinUppercase_Messages(t *testing.T) {

	assert.Equal(t, "Must contain at least 3 uppercase letters", MinUppercase(3).PasswordRuleDescription("en"))

	_, message := MinUppercase(3).ValidatePassword("ab")
	assert.Equal(t, "Password must contain at least 3 uppercase letters", message)
}

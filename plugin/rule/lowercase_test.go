package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinLowercase_ID(t *testing.T) {
	assert.Equal(t, "MinLowercase", MinLowercase(3).ID())
}

func TestMinLowercase_ValidatePassword(t *testing.T) {

	rule := MinLowercase(3)

	run := func(password string, expectedOK bool) {
		ok, message := rule.ValidatePassword(password)
		assert.Equal(t, expectedOK, ok, "password %q", password)
		if expectedOK {
			assert.Equal(t, "", message)
		} else {
			assert.NotEmpty(t, message)
		}
	}

	run("", false)        // 0 lowercase
	run("ABC123", false)  // 0 lowercase
	run("aB", false)      // 1 lowercase
	run("abC", false)     // 2 lowercase
	run("abc", true)      // 3 lowercase
	run("aBcDeF", true)   // 3 lowercase (a,c,e)
	run("password", true) // 8 lowercase
}

func TestMinLowercase_Messages(t *testing.T) {

	assert.Equal(t, "Must contain at least 3 lowercase letters", MinLowercase(3).PasswordRuleDescription())

	_, message := MinLowercase(3).ValidatePassword("AB")
	assert.Equal(t, "Password must contain at least 3 lowercase letters", message)
}

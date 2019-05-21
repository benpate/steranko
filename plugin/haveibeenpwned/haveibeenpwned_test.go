package haveibeenpwned

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHavedIBeenPwned(t *testing.T) {

	api := API{}

	assert.Equal(t, "Password can not appear on previously breached websites.  Visit https://haveibeenpwned.com for more info.", api.PasswordRuleDescription("en"))

	// One unique generated password, and apparently, Troubador73 doesn't show up in the password lists!!!
	for _, unique := range []string{"xeniBkP,o96TELz8skMJthQwwTBaG{+3", "F8DbXA4cY(dfh7r.CiCjEK6vACrcaeX$"} {
		ok, message := api.ValidatePassword(unique, "en")

		assert.True(t, ok)
		assert.Equal(t, "", message)
	}

	for _, pwned := range []string{"correcthorsebatterystaple", "hammer", "123456", "password", "password1"} {
		ok, message := api.ValidatePassword(pwned, "en")
		assert.False(t, ok)
		t.Log("Verifying password: " + pwned)
		t.Log(message)
	}
}

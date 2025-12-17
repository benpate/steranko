package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLength(t *testing.T) {

	plugin0 := MinLength(0)
	plugin1 := MinLength(1)
	plugin20 := MinLength(20)

	// Password Rule Descriptions
	{
		assert.Equal(t, "Must be at least 0 characters long", plugin0.PasswordRuleDescription("en"))
		assert.Equal(t, "Must be at least 1 characters long", plugin1.PasswordRuleDescription("en"))
		assert.Equal(t, "Must be at least 20 characters long", plugin20.PasswordRuleDescription("en"))
	}

	// Empty Password
	{
		ok, message := plugin0.ValidatePassword("", "en")

		assert.True(t, ok)
		assert.Equal(t, "", message)
	}

	// 1 Char Password
	{
		ok, message := plugin1.ValidatePassword("", "en")

		assert.False(t, ok)
		assert.Equal(t, "Password must be at least 1 characters long", message)
	}
	{
		ok, message := plugin1.ValidatePassword("x", "en")

		assert.True(t, ok)
		assert.Equal(t, "", message)
	}
	{
		ok, message := plugin1.ValidatePassword("xx", "en")

		assert.True(t, ok)
		assert.Equal(t, "", message)
	}

	{
		testValue := ""

		// 20 Char Password
		for x := 1; x < 30; x = x + 1 {
			testValue = testValue + "a"

			ok, message := plugin20.ValidatePassword(testValue, "en") // nolint:scopeguard readability

			if x < 20 {
				assert.False(t, ok)
				assert.Equal(t, "Password must be at least 20 characters long", message)
			} else {
				assert.True(t, ok)
				assert.Equal(t, "", message)
			}
		}
	}
}

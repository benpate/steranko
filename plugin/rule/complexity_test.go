package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMinComplexity_Name documents the only behavior MinComplexity currently
// implements. The type does not yet implement PasswordRuleDescription or
// ValidatePassword, so it is an incomplete plugin; this test will need to grow
// when that logic is added.
func TestMinComplexity_Name(t *testing.T) {
	assert.Equal(t, "MinComplexity", MinComplexity(1000).Name())
	assert.Equal(t, "MinComplexity", MinComplexity(0).Name())
}

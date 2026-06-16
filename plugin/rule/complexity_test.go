package rule

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinComplexity_ID(t *testing.T) {
	assert.Equal(t, "MinComplexity", MinComplexity(1000).ID())
	assert.Equal(t, "MinComplexity", MinComplexity(0).ID())
}

// TestCombinations exercises the keyspace estimate: pool size (per character
// class present) raised to the password length, saturating at MaxInt64.
func TestCombinations(t *testing.T) {

	assert.Equal(t, int64(0), Combinations(""))    // no characters, no keyspace
	assert.Equal(t, int64(0), Combinations("   ")) // no recognized character classes

	assert.Equal(t, int64(26), Combinations("a"))      // 26^1, lowercase only
	assert.Equal(t, int64(676), Combinations("ab"))    // 26^2
	assert.Equal(t, int64(17576), Combinations("abc")) // 26^3
	assert.Equal(t, int64(2704), Combinations("aB"))   // 52^2, lower+upper
	assert.Equal(t, int64(1296), Combinations("a1"))   // 36^2, lower+digit
	assert.Equal(t, int64(3364), Combinations("a!"))   // 58^2, lower+symbol

	// A long password overflows int64 and must saturate, never wrap negative.
	assert.Equal(t, int64(math.MaxInt64), Combinations(strings.Repeat("a", 20)))
}

func TestMinComplexity_ValidatePassword(t *testing.T) {

	rule := MinComplexity(1000)

	// "ab" -> 676 combinations, below the threshold.
	ok, message := rule.ValidatePassword("ab")
	assert.False(t, ok)
	assert.Equal(t, "Password must allow at least 1000 possible combinations", message)

	// "abc" -> 17576 combinations, at or above the threshold.
	ok, message = rule.ValidatePassword("abc")
	assert.True(t, ok)
	assert.Equal(t, "", message)

	// A threshold of zero accepts any password (including the empty string).
	ok, message = MinComplexity(0).ValidatePassword("")
	assert.True(t, ok)
	assert.Equal(t, "", message)
}

func TestMinComplexity_PasswordRuleDescription(t *testing.T) {
	assert.Equal(t, "Must allow at least 1000 possible combinations", MinComplexity(1000).PasswordRuleDescription("en"))
}

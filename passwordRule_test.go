package steranko

import (
	"testing"

	"github.com/benpate/steranko/plugin/haveibeenpwned"
	"github.com/benpate/steranko/plugin/rule"
	"github.com/stretchr/testify/require"
)

// Compile-time assertions that the bundled validators satisfy PasswordRule, so
// that a signature drift between a plugin and the interface fails the build.
var (
	_ PasswordRule = rule.MinLength(0)
	_ PasswordRule = rule.MinDigits(0)
	_ PasswordRule = rule.MinLowercase(0)
	_ PasswordRule = rule.MinUppercase(0)
	_ PasswordRule = rule.MinSymbols(0)
	_ PasswordRule = rule.MinComplexity(0)
	_ PasswordRule = &haveibeenpwned.API{}
)

// TestValidatePassword_BundledRulePlugin confirms a bundled rule plugin can be
// wired in through WithPasswordRules and is consulted by ValidatePassword.
func TestValidatePassword_BundledRulePlugin(t *testing.T) {

	s := getTestSteranko() // test schema requires length 10-20
	s.WithOptions(WithPasswordRules(rule.MinSymbols(2)))

	// Passes the schema (14 chars) but has only one symbol ("-") -> rejected.
	require.NotNil(t, s.ValidatePassword("valid-password"))

	// Passes the schema (12 chars) and has three symbols ("-", "!", "@") -> accepted.
	require.Nil(t, s.ValidatePassword("valid-pass!@"))
}

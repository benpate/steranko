package rule

// MinComplexity is a plugin that calculates the possible combinations of passwords, and validates against a minimum threshold.
type MinComplexity int64

// ID returns a string that uniquely identifies this plugin.
//
// NOTE: MinComplexity does not yet implement PasswordRuleDescription or
// ValidatePassword, so it does not satisfy steranko.PasswordRule.
func (rule MinComplexity) ID() string {
	return "MinComplexity"
}

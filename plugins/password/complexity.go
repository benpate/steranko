package password

// MinComplexity is a plugin that calculates the possible combinations of passwords, and validates against a minimum threshold.
type MinComplexity int64

// Name returns the name of this plugin, and is required for this object to implement the "Plugin" interface
func (rule MinComplexity) Name() string {
	return "MinComplexity"
}

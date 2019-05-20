package steranko

// Plugin defines
type Plugin interface {
	Name() string
}

// PasswordValidatorPlugin is used to verify if a password meets the password complexity criteria for this system.
type PasswordValidatorPlugin interface {

	// PasswordRuleDescription returns a map of language tags to human-readable strings that explain how the password can be used
	PasswordRuleDescription(language string) string

	// ValidatePassword returns TRUE if the password can be used in this system.  If not, it returns FALSE, and a message explaining why
	ValidatePassword(password string) (OK bool, errorMessage string)
}

// UsePlugin adds a plugin to the Steranko instance, so that it will be called at the appropriate points in the workflow.
// This should only be called during system startup and initialization.
func (s *Steranko) UsePlugin(plugin Plugin) {
	s.Plugins = append(s.Plugins, plugin)
}

// RemovePlugin removes a plugin (by name) from the Steranko instance, so that it will no longer be used.
// It returns TRUE if the plugin name was found in the current list.  Otherwise, FALSE,
// This should only be called during system startup and initialization.
func (s *Steranko) RemovePlugin(name string) bool {

	for index, plugin := range s.Plugins {

		if plugin.Name() == name {
			s.Plugins = append(s.Plugins[:index], s.Plugins[index+1:]...)
			return true
		}
	}

	return false
}
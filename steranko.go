package steranko

// Steranko contains all required configuration information for this library.
type Steranko struct {
	UserService UserService // Service that provides CRUD operations on Users
	Plugins     []Plugin    // Plugins registered to the system that provide additional business rules.
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService) *Steranko {
	return &Steranko{
		UserService: userService,
		Plugins:     []Plugin{}, // Will need to add default plugins here.
	}
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

package steranko

// Steranko contains all required configuration information for this library.
type Steranko struct {
	UserService UserService    // Service that provides CRUD operations on Users
	Plugins []Plugin           // Plugins registered to the system that provide additional business rules.
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(userService UserService) *Steranko {
	return &Steranko{
		UserService: userService,
		Plugins: []Plugin{}, // Will need to add default plugins here.
	}
}

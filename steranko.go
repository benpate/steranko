package steranko

import (
	"github.com/benpate/data"
)

// Steranko contains all required configuration information for this library.
type Steranko struct {
	Datastore data.Datastore    // Datastore used to save User account records.
	UserCollection string       // Name of the Datastore collection where user records are saved.
	MinimumPasswordStrength int // Numeric value used by bcrypt to set the
}

// New returns a fully initialized Steranko instance, with HandlerFuncs that support all of your user authentication and authorization needs.
func New(datastore data.Datastore) *Steranko {
	return &Steranko{
		Datastore: datastore,
		UserCollection: "Users", // This default can be overridden
		MinimumPasswordStrength: 10,
	}
}

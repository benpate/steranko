package steranko

import (
	"encoding/json"

	"github.com/benpate/derp"
	"github.com/benpate/schema"
)

// Authenticate verifies a username/password combination.
func (s *Steranko) Authenticate(username string, password string) (User, *derp.Error) {

	// Try to load the User from the UserService
	user, err := s.UserService.Load(username)

	if err != nil {

		if err.NotFound() {
			return nil, derp.New(CodeUnauthorized, "steranko.Authenticate", "Unauthorized", username)
		}

		return nil, derp.Wrap(err, "steranko.Authenticate", "Error loading User account", username)
	}

	// Fall through means that we have a matching user account.

	// Try to authenticate the password
	ok, update := s.PasswordHasher.CompareHashedPassword(password, user.GetPassword())

	if ok == false {
		return nil, derp.New(CodeUnauthorized, "steranko.Authenticate", "Unauthorized", username)
	}

	if update == true {

		if hashedValue, err := s.PasswordHasher.HashPassword(password); err == nil {
			user.SetPassword(hashedValue)
			_ = s.UserService.Save(user, "Password automatically upgraded by Steranko")
			// Intentionally ignoring errors updating the password because the user has already
			// authenticated.  If we can't update it now (for some reason) then we'll get it again, soon.
		}
	}

	return user, nil
}

// ValidatePassword checks a password against the requirements in the Config structure.
func (s *Steranko) ValidatePassword(password string) *derp.Error {

	if err := s.PasswordSchema().Validate(password); err != nil {
		return derp.Wrap(err, "steranko.ValidatePassword", "Password does not meet requirements")
	}

	return nil
}

// PasswordSchema returns the schema.Schema for validating passwords
func (s *Steranko) PasswordSchema() *schema.Schema {

	if s.passwordSchema == nil {
		s.passwordSchema = &schema.Schema{}
		json.Unmarshal([]byte(s.Config.PasswordSchema), s.passwordSchema)
	}

	return s.passwordSchema
}

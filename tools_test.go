package steranko

import (
	"testing"

	"github.com/benpate/schema"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {

	userService := getTestUserService()

	s := New(userService, Config{})

	{
		// Test successful signin
		user, err := s.Authenticate("michael@jackson.com", "hee-hee")
		require.Nil(t, err)
		require.NotNil(t, user)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		// Test bad password
		user, err := s.Authenticate("michael@jackson.com", "hoo-hoo")
		require.Nil(t, user)
		require.NotNil(t, err)
	}

	{
		// Test missing user
		user, err := s.Authenticate("kendall@jackson.com", "chardonay")
		require.Nil(t, user)
		require.NotNil(t, err)
	}
}

func TestValidatePassword(t *testing.T) {

	s := getTestSteranko()

	require.NotNil(t, s.ValidatePassword("too-short"))
	require.NotNil(t, s.ValidatePassword("this-password-is-way-too-long"))
	require.Nil(t, s.ValidatePassword("valid-password"))
}

func TestPasswordSchema(t *testing.T) {

	s := New(getTestUserService(), Config{
		PasswordSchema: `{"type":"string", "minLength":0, "maxLength":20}`,
	})

	sch := s.PasswordSchema()

	require.NotNil(t, sch)
	require.IsType(t, &schema.String{}, sch.Element)
	require.Equal(t, 0, sch.Element.(*schema.String).MinLength.Int())
	require.Equal(t, 20, sch.Element.(*schema.String).MaxLength.Int())
}

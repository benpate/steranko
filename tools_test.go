package steranko

import (
	"encoding/json"
	"testing"

	"github.com/benpate/rosetta/schema"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {

	s := getTestSteranko()

	{
		// Test successful signin
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hee-hee", user)
		require.Nil(t, err)
		require.NotNil(t, user)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		// Test bad password
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hoo-hoo", user)
		require.NotNil(t, err)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		// Test missing user
		user := s.userService.New()
		err := s.authenticate("kendall@jackson.com", "chardonay", user)
		require.NotNil(t, err)
		require.Equal(t, "", user.GetUsername())
		require.Equal(t, "", user.GetPassword())
	}
}

func TestValidatePassword(t *testing.T) {

	s := getTestSteranko()

	require.NotNil(t, s.ValidatePassword("too-short"))
	require.NotNil(t, s.ValidatePassword("this-password-is-way-too-long"))
	require.Nil(t, s.ValidatePassword("valid-password"))
}

func TestPasswordSchema(t *testing.T) {

	var input schema.Schema

	err := json.Unmarshal([]byte(`{"type":"string", "minLength":0, "maxLength":20}`), &input)
	require.Nil(t, err)

	s := New(getTestUserService(), getTestKeyService(), WithPasswordSchema(input))
	sch := s.passwordSchema

	require.NotNil(t, sch)
	require.IsType(t, schema.String{}, sch.Element)
	require.Equal(t, 0, sch.Element.(schema.String).MinLength)
	require.Equal(t, 20, sch.Element.(schema.String).MaxLength)
}

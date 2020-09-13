package steranko

import (
	"testing"

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

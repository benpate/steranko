package steranko

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {

	userService := testNewUserService()

	mike := userService.New()
	mike.SetUsername("michael@jackson.com")
	mike.SetPassword("hee-hee")

	err := userService.Save(mike, "Creating Mike")
	require.Nil(t, err)

	s := New(userService, Config{})

	{
		user, err := s.Authenticate("michael@jackson.com", "hee-hee")
		require.Nil(t, err)
		require.NotNil(t, user)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		user, err := s.Authenticate("michael@jackson.com", "hoo-hoo")
		require.Nil(t, user)
		require.NotNil(t, err)
	}

}

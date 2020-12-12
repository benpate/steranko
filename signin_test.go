package steranko

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostSignin_Success(t *testing.T) {

	s := getTestSteranko()

	transaction := SigninTransaction{
		Username: "andrew@jackson.com",
		Password: "whitehouse",
	}

	result := s.Signin(transaction)

	require.Nil(t, result.Error)
	require.Empty(t, result.ErrorMessage)
	require.Equal(t, "andrew@jackson.com", result.Username)
	require.NotEmpty(t, result.JWT)
}

func TestPostSignin_Failure(t *testing.T) {

	s := getTestSteranko()

	transaction := SigninTransaction{
		Username: "andrew@jackson.com",
		Password: "bad-password",
	}

	result := s.Signin(transaction)

	require.NotNil(t, result.Error)
	require.NotEmpty(t, result.ErrorMessage)
	require.Equal(t, "andrew@jackson.com", result.Username)
	require.Empty(t, result.JWT)
}

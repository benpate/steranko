package hash

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBCrypt(t *testing.T) {

	p := BCrypt(10)

	require.Equal(t, "BCrypt", p.ID())

	// https://www.xkcd.com/936/
	testValues := []string{"trombone", "Tr0ub4dor&3", "correcthorsebatterystaple", "we hold these truths to be self evident, that all men are created equal, and are endowed by their creator with certain inalienable rights.  That among these rights are Life, Liberty, and the Pursuit of Happiness."}

	for _, plaintext := range testValues {

		hashedValue, err := p.HashPassword(plaintext)
		require.NotEqual(t, plaintext, hashedValue)
		require.Nil(t, err)

		// Test incorrect password
		{
			ok, update := p.CompareHashedPassword(hashedValue, "not-the-password")
			require.False(t, ok)
			require.False(t, update)
			require.Equal(t, 60, len(hashedValue))
		}

		// Test matching password
		{
			ok, update := p.CompareHashedPassword(hashedValue, plaintext)
			require.True(t, ok)
			require.False(t, update)
		}

		// Test out-of-date cipher
		{
			newCipher := BCrypt(11)
			ok, update := newCipher.CompareHashedPassword(hashedValue, plaintext)
			require.True(t, ok)
			require.True(t, update)
		}
	}
}

func TestMaxlength(t *testing.T) {
	require.Equal(t, "hello", maxlength("hello", 10))
	require.Equal(t, "hell", maxlength("hello", 4))
}

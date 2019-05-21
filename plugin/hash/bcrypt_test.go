package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBCrypt(t *testing.T) {

	p := BCrypt(10)

	assert.Equal(t, "BCrypt", p.ID())

	// https://www.xkcd.com/936/
	testValues := []string{"trombone", "Tr0ub4dor&3", "correcthorsebatterystaple", "we hold these truths to be self evident, that all men are created equal, and are endowed by their creator with certain inalienable rights.  That among these rights are Life, Liberty, and the Persuit of Happiness."}

	for _, plaintext := range testValues {

		hashedValue, err := p.HashPassword(plaintext)
		assert.NotEqual(t, plaintext, hashedValue)
		assert.Nil(t, err)

		// Test incorrect password
		{
			ok, update := p.CompareHashedPassword(hashedValue, "not-the-password")
			assert.False(t, ok)
			assert.False(t, update)
			assert.Equal(t, 60, len(hashedValue))
		}

		// Test matching password
		{
			ok, update := p.CompareHashedPassword(hashedValue, plaintext)
			assert.True(t, ok)
			assert.False(t, update)
		}

		// Test out-of-date cipher
		{
			newCipher := BCrypt(11)
			ok, update := newCipher.CompareHashedPassword(hashedValue, plaintext)
			assert.True(t, ok)
			assert.True(t, update)
		}
	}
}

package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlaintext(t *testing.T) {

	p := Plaintext{}

	assert.Equal(t, "Plaintext", p.ID())

	// https://www.xkcd.com/936/
	testValues := []string{"trombone", "Tr0ub4dor&3", "correcthorsebatterystaple", "we hold these truths to be self evident, that all men are created equal, and are endowed by their creator with certain inalienable rights.  That among these rights are Life, Liberty, and the Persuit of Happiness."}

	for _, plaintext := range testValues {

		hashedValue, err := p.HashPassword(plaintext)
		assert.Equal(t, plaintext, hashedValue)
		assert.Nil(t, err)

		{
			ok, update := p.CompareHashedPassword(hashedValue, plaintext)
			assert.True(t, ok)
			assert.True(t, update)
		}

		{
			ok, update := p.CompareHashedPassword(hashedValue, "literally anything else")
			assert.False(t, ok)
			assert.True(t, update)
		}
	}
}

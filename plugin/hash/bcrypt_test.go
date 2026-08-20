package hash

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
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

		// Test out-of-date cipher (stored cost LOWER than configured => upgrade)
		{
			newCipher := BCrypt(11)
			ok, update := newCipher.CompareHashedPassword(hashedValue, plaintext)
			require.True(t, ok)
			require.True(t, update)
		}

		// Test over-cost cipher (stored cost HIGHER than configured => downgrade,
		// retiring the slower comparison)
		{
			newCipher := BCrypt(9)
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

// TestBCrypt_RejectsUnaffordableCost is the regression test for a hang found by
// FuzzBCryptCompareHashedPassword. bcrypt reads its work factor out of the stored
// hash, so a value claiming a high cost makes a single comparison run for minutes
// (cost 24) or days (cost 31) -- on an unauthenticated signin attempt. The cost is
// parsed in microseconds, so the check must happen BEFORE the comparison.
func TestBCrypt_RejectsUnaffordableCost(t *testing.T) {

	bc := BCrypt(4)

	require.Equal(t, 15, MaximumCost, "the ceiling is part of the contract; changing it changes who can sign in")

	// Both crashers the fuzzer produced. bcrypt tolerates a zero-padded cost field and a
	// junk version field, so neither needs to be a well-formed hash to demand 2^20 or 2^24
	// rounds of work.
	for _, crafted := range []string{
		"$00024$abcdefghijkxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxlmnopqrst",
		"$0$20000000000000000000000000000000000000000000000000000000",
	} {
		// Confirm the input really does declare a cost this package must refuse.
		cost, err := bcrypt.Cost([]byte(crafted))
		require.Nil(t, err)
		require.Greater(t, cost, MaximumCost, "input %q", crafted)

		// The rejection must be immediate. Without the guard these run for a minute (cost 20)
		// to a quarter hour (cost 24), so the deadline IS the assertion -- generous enough to
		// stay stable under -race on a loaded machine, and still orders of magnitude faster
		// than honoring the declared cost.
		start := time.Now()
		ok, rehash := bc.CompareHashedPassword(crafted, "password")
		elapsed := time.Since(start)

		require.False(t, ok, "input %q", crafted)
		require.False(t, rehash, "input %q", crafted)
		require.Less(t, elapsed, 5*time.Second, "an unaffordable cost must be refused, not honored")
	}
}

// TestBCrypt_ConfiguredCostRaisesTheCeiling confirms the ceiling never locks an application
// out of its OWN hashes. An app that deliberately configures an expensive cost has accepted
// what that costs; a fixed ceiling below it would reject every password it ever stored.
func TestBCrypt_ConfiguredCostRaisesTheCeiling(t *testing.T) {

	expensive := BCrypt(MaximumCost + 2)
	require.Equal(t, MaximumCost+2, expensive.maximumCost())

	// And the default hasher does NOT have its ceiling lowered by a small configured cost.
	require.Equal(t, MaximumCost, BCrypt(4).maximumCost())
}

// TestBCrypt_HonorsAffordableCost confirms the ceiling did not break the legacy-hash
// upgrade path: a hash stored at a DIFFERENT but affordable cost must still verify,
// and must still be flagged for re-hashing.
func TestBCrypt_HonorsAffordableCost(t *testing.T) {

	// Stored at cost 5, verified by a service now configured for cost 4.
	hashed, err := BCrypt(5).HashPassword("password")
	require.Nil(t, err)

	ok, rehash := BCrypt(4).CompareHashedPassword(hashed, "password")
	require.True(t, ok, "an affordable legacy cost must still verify")
	require.True(t, rehash, "and must be flagged for re-hashing at the configured cost")
}

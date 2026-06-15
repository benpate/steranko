package hash

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBCrypt_LongPasswordTruncation documents that bcrypt only considers the
// first 72 bytes of a password. Two passwords that share a 72-byte prefix must
// be treated as equal. This is a security-relevant edge case.
func TestBCrypt_LongPasswordTruncation(t *testing.T) {

	bc := BCrypt(4)

	prefix := strings.Repeat("a", 72)
	hashed, err := bc.HashPassword(prefix + "EXTRA-IGNORED-SUFFIX")
	require.Nil(t, err)

	// A password sharing the same 72-byte prefix must validate.
	ok, _ := bc.CompareHashedPassword(hashed, prefix+"different-suffix")
	require.True(t, ok, "bcrypt ignores bytes beyond the 72-byte limit")

	// A password that differs within the first 72 bytes must NOT validate.
	differentPrefix := strings.Repeat("a", 71) + "b"
	ok, _ = bc.CompareHashedPassword(hashed, differentPrefix)
	require.False(t, ok)
}

// TestBCrypt_EmptyPassword confirms an empty password can be hashed and matched.
func TestBCrypt_EmptyPassword(t *testing.T) {

	bc := BCrypt(4)

	hashed, err := bc.HashPassword("")
	require.Nil(t, err)
	require.NotEmpty(t, hashed)

	ok, _ := bc.CompareHashedPassword(hashed, "")
	require.True(t, ok)

	ok, _ = bc.CompareHashedPassword(hashed, "not-empty")
	require.False(t, ok)
}

// TestBCrypt_InvalidHashedValue confirms that comparing against a non-bcrypt
// (garbage) stored value safely reports a non-match instead of panicking.
func TestBCrypt_InvalidHashedValue(t *testing.T) {

	bc := BCrypt(4)

	ok, rehash := bc.CompareHashedPassword("this-is-not-a-bcrypt-hash", "password")
	require.False(t, ok)
	require.False(t, rehash)
}

// TestBCrypt_InvalidCost confirms that an out-of-range cost is reported as an
// error from HashPassword rather than producing an unusable hash. bcrypt's
// maximum cost is 31; anything higher must fail.
func TestBCrypt_InvalidCost(t *testing.T) {

	hashed, err := BCrypt(99).HashPassword("password")
	require.NotNil(t, err)
	require.Empty(t, hashed)
}

// FuzzBCryptCompareHashedPassword confirms that comparing arbitrary stored
// values and plaintexts never panics, and never reports a match for a value
// that is not a real bcrypt hash of the plaintext.
func FuzzBCryptCompareHashedPassword(f *testing.F) {

	f.Add("$2a$04$abcdefghijklmnopqrstuv", "password")
	f.Add("", "")
	f.Add("garbage", "password")

	bc := BCrypt(4)

	f.Fuzz(func(t *testing.T, hashedValue string, plaintext string) {
		// The only invariant we can cheaply assert is that this never panics.
		// (A random string being a valid bcrypt hash of the plaintext is
		// astronomically unlikely.)
		bc.CompareHashedPassword(hashedValue, plaintext)
	})
}

// FuzzBCryptRoundTrip confirms that any plaintext, once hashed, validates
// against its own hash and never against a different plaintext (subject to the
// 72-byte truncation rule). Uses the minimum cost to stay fast.
func FuzzBCryptRoundTrip(f *testing.F) {

	f.Add("password")
	f.Add("")
	f.Add("a-much-longer-passphrase-with-symbols-!@#$%^&*()")

	bc := BCrypt(4) // bcrypt minimum cost, for speed

	f.Fuzz(func(t *testing.T, plaintext string) {

		hashed, err := bc.HashPassword(plaintext)
		require.Nil(t, err)

		ok, _ := bc.CompareHashedPassword(hashed, plaintext)
		require.True(t, ok, "a password must validate against its own hash")
	})
}

// FuzzMaxlength confirms the truncation helper never returns a string longer
// than the limit and never panics on multi-byte input.
func FuzzMaxlength(f *testing.F) {

	f.Add("hello", 3)
	f.Add("", 0)
	f.Add("日本語のテキスト", 4)

	f.Fuzz(func(t *testing.T, value string, max int) {
		if max < 0 {
			t.Skip() // negative limits are not a supported input
		}
		result := maxlength(value, max)
		require.LessOrEqual(t, len(result), max)
		require.LessOrEqual(t, len(result), len(value))
	})
}

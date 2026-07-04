package steranko

import (
	"strings"
	"testing"

	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Tests in this file use hash.BCrypt(bcrypt.MinCost) so that the chain mechanics
// can be exercised quickly; the cost setting itself is application policy.

// TestNewPasswordService_Default confirms that an empty constructor installs the
// default hasher — which must NOT be plaintext, because this is a security package.
func TestNewPasswordService_Default(t *testing.T) {

	service := NewPasswordService()

	require.Len(t, service.hashers, 1)
	require.Equal(t, "BCrypt", service.primary().ID())
}

// TestPasswordService_PrimaryIsFirst pins the one rule the type exists to own:
// the first hasher in the chain creates all new password hashes.
func TestPasswordService_PrimaryIsFirst(t *testing.T) {

	service := NewPasswordService(hash.Plaintext{}, hash.BCrypt(bcrypt.MinCost))
	require.Equal(t, "Plaintext", service.primary().ID())
}

// TestPasswordService_ZeroValue confirms that a zero-value PasswordService still
// hashes with the default hasher instead of panicking.  ComparePassword on a
// zero value matches nothing, which is the safe failure mode.
func TestPasswordService_ZeroValue(t *testing.T) {

	service := PasswordService{}

	hashedValue, err := service.HashPassword("hunter2")
	require.Nil(t, err)
	require.NotEqual(t, "hunter2", hashedValue)

	ok, _ := service.ComparePassword("hunter2", hashedValue)
	require.False(t, ok, "zero-value chain has no verifiers; compare must fail closed")
}

// TestPasswordService_SetPassword confirms that SetPassword stores a hash of the
// plaintext — never the plaintext itself — and that the hash round-trips.
func TestPasswordService_SetPassword(t *testing.T) {

	service := NewPasswordService(hash.BCrypt(bcrypt.MinCost))

	user := &testUser{}
	require.Nil(t, service.SetPassword(user, "TestPass123!"))

	require.NotEqual(t, "TestPass123!", user.Password)
	require.True(t, strings.HasPrefix(user.Password, "$2"))

	ok, rehash := service.ComparePassword("TestPass123!", user.Password)
	require.True(t, ok)
	require.False(t, rehash)

	ok, _ = service.ComparePassword("WrongPass123!", user.Password)
	require.False(t, ok)
}

// TestPasswordService_UniqueSalts confirms that hashing the same plaintext twice
// yields different stored values.  Identical values would mean the salt is broken.
func TestPasswordService_UniqueSalts(t *testing.T) {

	service := NewPasswordService(hash.BCrypt(bcrypt.MinCost))

	first, err := service.HashPassword("TestPass123!")
	require.Nil(t, err)

	second, err := service.HashPassword("TestPass123!")
	require.Nil(t, err)

	require.NotEqual(t, first, second)
}

// TestPasswordService_FallbackFlagsRehash pins the upgrade contract: a value that
// only matches a non-primary hasher verifies successfully, but is flagged for
// re-hashing with the primary.
func TestPasswordService_FallbackFlagsRehash(t *testing.T) {

	service := NewPasswordService(hash.BCrypt(bcrypt.MinCost), hash.Plaintext{})

	// A legacy plaintext-stored value matches the Plaintext fallback => ok + rehash
	ok, rehash := service.ComparePassword("legacy-password", "legacy-password")
	require.True(t, ok)
	require.True(t, rehash)

	// A primary-hashed value matches the primary => ok, no rehash
	hashedValue, err := service.HashPassword("current-password")
	require.Nil(t, err)

	ok, rehash = service.ComparePassword("current-password", hashedValue)
	require.True(t, ok)
	require.False(t, rehash)
}

// TestPasswordService_BCryptTruncation pins the bcrypt input limit as the hasher
// handles it: input beyond 72 bytes is silently ignored, on both the hashing and
// comparison sides.  Generated passwords (e.g. lockout values) must stay under
// this limit to preserve their full entropy.
func TestPasswordService_BCryptTruncation(t *testing.T) {

	service := NewPasswordService(hash.BCrypt(bcrypt.MinCost))
	prefix := strings.Repeat("a", 72)

	hashedValue, err := service.HashPassword(prefix + "tail-1")
	require.Nil(t, err)

	// A different password sharing the first 72 bytes still verifies (the tail is ignored) ...
	ok, _ := service.ComparePassword(prefix+"tail-2", hashedValue)
	require.True(t, ok)

	// ... but a difference within the first 72 bytes does not
	ok, _ = service.ComparePassword("b"+prefix[1:], hashedValue)
	require.False(t, ok)
}

// FuzzPasswordService_SetPassword asserts the core property across arbitrary
// inputs: SetPassword never errors, never panics, never stores the plaintext, and
// always produces a hash that verifies against the original input.
func FuzzPasswordService_SetPassword(f *testing.F) {

	f.Add("")
	f.Add("TestPass123!")
	f.Add("pässwörd-ünïcödé")
	f.Add(strings.Repeat("a", 71))
	f.Add(strings.Repeat("a", 72))
	f.Add(strings.Repeat("a", 100))
	f.Add("pass\xff\xfe\xfdword")

	service := NewPasswordService(hash.BCrypt(bcrypt.MinCost))

	f.Fuzz(func(t *testing.T, plaintext string) {

		user := &testUser{}

		if err := service.SetPassword(user, plaintext); err != nil {
			t.Fatalf("SetPassword must not error, got: %v", err)
		}

		if user.Password == plaintext {
			t.Fatalf("plaintext stored verbatim for input %q", plaintext)
		}

		if ok, _ := service.ComparePassword(plaintext, user.Password); !ok {
			t.Fatalf("hash does not verify against original input %q", plaintext)
		}
	})
}

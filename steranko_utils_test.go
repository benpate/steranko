package steranko

import (
	"testing"

	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/require"
)

func TestSetPassword(t *testing.T) {

	// With the Plaintext hasher the stored value equals the plaintext.
	{
		s := getTestSteranko() // configured with hash.Plaintext{}
		user := s.userService.New()
		require.Nil(t, s.SetPassword(user, "hunter2"))
		require.Equal(t, "hunter2", user.GetPassword())
	}

	// With a BCrypt hasher the stored value must be hashed (never plaintext).
	{
		s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hash.BCrypt(4)))
		user := s.userService.New()
		require.Nil(t, s.SetPassword(user, "hunter2"))
		require.NotEqual(t, "hunter2", user.GetPassword())
		require.NotEmpty(t, user.GetPassword())
	}
}

func TestComparePassword(t *testing.T) {

	// Build a Steranko with a primary (BCrypt) and a deprecated (Plaintext)
	// hasher so we can exercise the "needs upgrade" path.
	s := New(
		getTestUserService(),
		getTestKeyService(),
		WithPasswordHasher(hash.BCrypt(4), hash.Plaintext{}),
	)

	// A value that matches the PRIMARY hasher: ok=true, update=false.
	primaryHash, err := hash.BCrypt(4).HashPassword("secret-password")
	require.Nil(t, err)
	{
		ok, update := s.ComparePassword("secret-password", primaryHash)
		require.True(t, ok)
		require.False(t, update, "a primary-hash match should not require a rehash")
	}

	// A value that only matches a DEPRECATED hasher: ok=true, update=true.
	{
		ok, update := s.ComparePassword("secret-password", "secret-password") // plaintext match
		require.True(t, ok)
		require.True(t, update, "a deprecated-hash match must be flagged for upgrade")
	}

	// A value that matches no hasher: ok=false, update=false.
	{
		ok, update := s.ComparePassword("wrong-password", primaryHash)
		require.False(t, ok)
		require.False(t, update)
	}
}

func TestGetPasswordHasher(t *testing.T) {

	// The first configured hasher is the primary hasher.
	{
		s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hash.Plaintext{}, hash.BCrypt(4)))
		require.Equal(t, "Plaintext", s.getPasswordHasher().ID())
	}

	// When the hasher list is empty, the default (BCrypt) hasher is returned.
	// This is a defensive fallback; New always installs a default, so it is
	// only reachable by explicitly clearing the slice.
	{
		s := New(getTestUserService(), getTestKeyService())
		s.passwordHashers = nil
		require.Equal(t, "BCrypt", s.getPasswordHasher().ID())
	}
}

func TestDefaultPasswordHasher(t *testing.T) {

	// The default hasher must be BCrypt with the package's configured cost.
	hasher := defaultPasswordHasher()
	require.Equal(t, "BCrypt", hasher.ID())
	require.Equal(t, hash.BCrypt(15), hasher)
}

// TestAuthenticate_UpgradesPassword confirms that authenticating against a
// deprecated hash automatically re-hashes and persists the password with the
// primary hasher.
func TestAuthenticate_UpgradesPassword(t *testing.T) {

	s := New(
		getTestUserService(),
		getTestKeyService(),
		WithPasswordHasher(hash.BCrypt(4), hash.Plaintext{}),
	)

	// Seed a user whose stored password is a (deprecated) plaintext value.
	seed := s.userService.New()
	seed.SetUsername("upgrade@example.com")
	seed.SetPassword("plaintext-password")
	require.Nil(t, s.userService.Save(seed, "seed"))

	// Authenticate with the correct password.
	user := s.userService.New()
	require.Nil(t, s.authenticate("upgrade@example.com", "plaintext-password", user))

	// After authentication the stored password should have been upgraded to a
	// BCrypt hash (no longer equal to the plaintext value).
	reloaded := s.userService.New()
	require.Nil(t, s.userService.Load("upgrade@example.com", reloaded))
	require.NotEqual(t, "plaintext-password", reloaded.GetPassword())

	// And the upgraded hash must still authenticate the original password.
	ok, update := s.ComparePassword("plaintext-password", reloaded.GetPassword())
	require.True(t, ok)
	require.False(t, update, "after upgrade the password should match the primary hasher")
}

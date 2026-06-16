package steranko

import (
	"errors"
	"testing"

	"github.com/benpate/derp"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/require"
)

// countingHasher is a test PasswordHasher that records how many times it is
// asked to hash or compare, so tests can assert that work happened without
// relying on (flaky) wall-clock timing.
type countingHasher struct {
	hashes   *int
	compares *int
}

func (countingHasher) ID() string { return "counting" }

func (h countingHasher) HashPassword(plaintext string) (string, error) {
	*h.hashes++
	return "hashed:" + plaintext, nil
}

func (h countingHasher) CompareHashedPassword(hashedValue string, plaintext string) (bool, bool) {
	*h.compares++
	return hashedValue == "hashed:"+plaintext, false
}

// failHashHasher is a test PasswordHasher whose HashPassword always fails, used
// to exercise the decoy-hash fallback path.
type failHashHasher struct{}

func (failHashHasher) ID() string { return "fail-hash" }

func (failHashHasher) HashPassword(plaintext string) (string, error) {
	return "", errors.New("cannot hash")
}

func (failHashHasher) CompareHashedPassword(hashedValue string, plaintext string) (bool, bool) {
	return false, false
}

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

// TestAuthenticate_DecoyComparisonOnUnknownUser confirms that authenticating an
// unknown user still performs a password comparison (against a decoy hash), so
// the timing matches a real password check and usernames cannot be enumerated.
func TestAuthenticate_DecoyComparisonOnUnknownUser(t *testing.T) {

	var hashes, compares int
	hasher := countingHasher{hashes: &hashes, compares: &compares}

	s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hasher))

	// Authenticate a user that does not exist.
	err := s.authenticate("nobody@nowhere.com", "any-password", s.userService.New())

	require.NotNil(t, err)
	require.True(t, derp.IsUnauthorized(err))
	require.Equal(t, 1, hashes, "the decoy hash should be generated exactly once")
	require.GreaterOrEqual(t, compares, 1, "a decoy comparison must run on the not-found path")

	// A second unknown-user signin must reuse the cached decoy hash (no second
	// hash generation) while still performing a comparison.
	err = s.authenticate("also-nobody@nowhere.com", "any-password", s.userService.New())

	require.NotNil(t, err)
	require.Equal(t, 1, hashes, "the decoy hash must be cached, not regenerated")
	require.GreaterOrEqual(t, compares, 2, "a decoy comparison must run on every not-found signin")
}

// TestDecoyPasswordHash confirms the decoy hash is non-empty, cached (stable
// across calls), and a valid hash that does not match an arbitrary password.
func TestDecoyPasswordHash(t *testing.T) {

	s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hash.BCrypt(4)))

	first := s.decoyPasswordHash()
	require.NotEmpty(t, first)
	require.Equal(t, first, s.decoyPasswordHash(), "decoy hash must be stable across calls")

	// The decoy must not accidentally validate a real password.
	ok, _ := s.ComparePassword("any-password", first)
	require.False(t, ok)
}

// TestDecoyPasswordHash_FallbackOnHasherFailure confirms that a primary hasher
// which cannot produce a hash still yields a (default-hashed) decoy, so the
// timing-equalizing comparison is never skipped.
func TestDecoyPasswordHash_FallbackOnHasherFailure(t *testing.T) {

	s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(failHashHasher{}))

	require.NotEmpty(t, s.decoyPasswordHash(), "decoy must fall back to a valid hash when the primary hasher fails")
}

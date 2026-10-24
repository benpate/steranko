package steranko

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/benpate/derp"
	"github.com/benpate/derp/plugins"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/assert"
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

// captureReporter is a derp.Reporter that keeps every error reported to it.
type captureReporter struct {
	errors []error
}

// Report appends the error to the captured list.
func (r *captureReporter) Report(err error) {
	r.errors = append(r.errors, err)
}

// captureReports sends every derp.Report to a new captureReporter until the test ends.
func captureReports(t *testing.T) *captureReporter {
	t.Helper()

	reporter := &captureReporter{}
	derp.SetPlugins(reporter)
	t.Cleanup(func() { derp.SetPlugins(plugins.JSON{}) })

	return reporter
}

// requireNotLeaked fails when the JSON a reporter would store for err contains secret.
func requireNotLeaked(t *testing.T, err error, secret string) {
	t.Helper()

	encoded, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)
	require.NotContains(t, string(encoded), secret, "the error must not carry %q", secret)
}

func TestSetPassword(t *testing.T) {

	// With the Plaintext hasher the stored value equals the plaintext.
	{
		s := getTestSteranko() // configured with hash.Plaintext{}
		user := s.userService.New()
		require.Nil(t, s.SetPassword(user, "hunter2"))
		require.Equal(t, "hunter2", user.GetHashedPassword())
	}

	// With a BCrypt hasher the stored value must be hashed (never plaintext).
	{
		s := New(getTestUserService(), getTestKeyService(), WithPasswordHasher(hash.BCrypt(4)))
		user := s.userService.New()
		require.Nil(t, s.SetPassword(user, "hunter2"))
		require.NotEqual(t, "hunter2", user.GetHashedPassword())
		require.NotEmpty(t, user.GetHashedPassword())
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

func TestDefaultPasswordHasher(t *testing.T) {

	// The default hasher must be BCrypt with the package's configured cost.
	hasher := defaultPasswordHasher()
	require.Equal(t, "BCrypt", hasher.ID())
	require.Equal(t, hash.BCrypt(12), hasher)
}

func TestAuthenticate(t *testing.T) {

	s := getTestSteranko()

	{
		// Test successful signin
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hee-hee", user)
		require.Nil(t, err)
		require.NotNil(t, user)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetHashedPassword())
	}

	{
		// Test bad password
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hoo-hoo", user)
		require.NotNil(t, err)
		require.True(t, derp.IsUnauthorized(err))
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetHashedPassword())
		requireNotLeaked(t, err, "hoo-hoo")
		requireNotLeaked(t, err, "hee-hee")
	}

	{
		// Test missing user
		user := s.userService.New()
		err := s.authenticate("kendall@jackson.com", "chardonay", user)
		require.NotNil(t, err)
		require.True(t, derp.IsUnauthorized(err))
		require.Equal(t, "", user.GetUsername())
		require.Equal(t, "", user.GetHashedPassword())
		requireNotLeaked(t, err, "chardonay")
	}
}

// TestAuthenticate_FailuresLookAlike confirms that a wrong password and an unknown account
// return the same code and message, so the answer cannot reveal which accounts exist.
func TestAuthenticate_FailuresLookAlike(t *testing.T) {

	s := getTestSteranko()

	wrongPassword := s.authenticate("michael@jackson.com", "hoo-hoo", s.userService.New())
	unknownUser := s.authenticate("kendall@jackson.com", "hoo-hoo", s.userService.New())

	require.Error(t, wrongPassword)
	require.Error(t, unknownUser)
	require.Equal(t, derp.ErrorCode(wrongPassword), derp.ErrorCode(unknownUser))
	require.Equal(t, derp.Message(wrongPassword), derp.Message(unknownUser))
	require.Equal(t, derp.Location(wrongPassword), derp.Location(unknownUser))
}

// TestAuthenticate_EmptyPassword confirms that an empty password is refused before any
// account is loaded or any password is compared, whatever the username names.
func TestAuthenticate_EmptyPassword(t *testing.T) {

	// check runs one empty-password signin against a fresh Steranko
	check := func(name string, username string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {

			var hashes, compares int
			accounts := map[string]string{
				"michael@jackson.com": "hashed:hee-hee",
				"blank@example.com":   "",
			}
			s, spy := newAccountsSteranko(accounts, countingHasher{hashes: &hashes, compares: &compares})
			user := s.userService.New()

			err := s.authenticate(username, "", user)

			// The guard answers with its own BadRequest
			require.Error(t, err)
			assert.True(t, derp.IsBadRequest(err), "got code %d", derp.ErrorCode(err))
			assert.Equal(t, "steranko.authenticate", derp.Location(err))
			assert.Equal(t, "Password is required", derp.Message(err))

			// RULE: Nothing runs past the guard: no lookup, no comparison, no decoy hash
			assert.Zero(t, spy.loads, "the user store must not be consulted")
			assert.Zero(t, spy.saves, "nothing may be saved")
			assert.Zero(t, compares, "no password comparison may run")
			assert.Zero(t, hashes, "the decoy hash must not be computed")

			// The caller's User is left empty, and no account is changed
			assert.Empty(t, user.GetUsername())
			assert.Empty(t, user.GetHashedPassword())
			assert.Equal(t, map[string]string{"michael@jackson.com": "hashed:hee-hee", "blank@example.com": ""}, accounts)
		})
	}

	check("existing account", "michael@jackson.com")
	check("account with no stored password", "blank@example.com")
	check("unknown account", "nobody@nowhere.com")
	check("empty username", "")
	check("whitespace username", "   ")
	check("NUL username", "\x00")
	check("invalid UTF-8 username", "\xff\xfe")
	check("very long username", strings.Repeat("a", 1<<16))
}

// TestAuthenticate_EmptyPasswordAgainstBlankHash confirms that an empty password cannot
// sign in to an account whose stored hash the hasher chain would accept for "".
func TestAuthenticate_EmptyPasswordAgainstBlankHash(t *testing.T) {

	// check seeds one account, confirms the hashers alone admit "", then confirms authenticate does not
	check := func(name string, storedHash string, hashers ...PasswordHasher) {
		t.Helper()
		t.Run(name, func(t *testing.T) {

			accounts := map[string]string{"blank@example.com": storedHash}
			s, spy := newAccountsSteranko(accounts, hashers...)

			// Without the guard, this chain would sign the account in
			ok, _ := s.ComparePassword("", storedHash)
			require.True(t, ok, "precondition: the hasher chain must match an empty password")

			err := s.authenticate("blank@example.com", "", s.userService.New())

			require.Error(t, err)
			assert.True(t, derp.IsBadRequest(err), "got code %d", derp.ErrorCode(err))
			assert.Zero(t, spy.loads, "the account must not be loaded")
			assert.Zero(t, spy.saves, "a refused signin must not upgrade the stored hash")
			assert.Equal(t, storedHash, accounts["blank@example.com"], "the stored hash must not change")
		})
	}

	blankBCrypt, err := hash.BCrypt(4).HashPassword("")
	require.NoError(t, err)

	check("Plaintext, nothing stored", "", hash.Plaintext{})
	check("BCrypt with Plaintext fallback, nothing stored", "", hash.BCrypt(4), hash.Plaintext{})
	check("BCrypt, stored hash of the empty string", blankBCrypt, hash.BCrypt(4))
	check("BCrypt with Plaintext fallback, stored hash of the empty string", blankBCrypt, hash.BCrypt(4), hash.Plaintext{})
}

// TestAuthenticate_BlankLookingPasswords confirms that the guard matches "" alone, so a
// password of whitespace or control characters still goes through a real comparison.
func TestAuthenticate_BlankLookingPasswords(t *testing.T) {

	// check signs in to an account with no stored password, using a non-empty password
	check := func(name string, password string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {

			var hashes, compares int
			s, spy := newAccountsSteranko(map[string]string{"blank@example.com": ""}, countingHasher{hashes: &hashes, compares: &compares})

			err := s.authenticate("blank@example.com", password, s.userService.New())

			require.Error(t, err)
			assert.True(t, derp.IsUnauthorized(err), "got code %d", derp.ErrorCode(err))
			assert.Equal(t, 1, spy.loads, "the account must be loaded")
			assert.Equal(t, 1, compares, "the password must be compared")
		})
	}

	check("single space", " ")
	check("tab", "\t")
	check("newline", "\n")
	check("NUL byte", "\x00")
	check("zero-width space", "\xe2\x80\x8b")
	check("invalid UTF-8", "\xff")
}

// TestAuthenticate_DecoyPlaintextIsNotAPassword confirms that an unknown account is refused
// even when the password is the decoy hash's own plaintext.
func TestAuthenticate_DecoyPlaintextIsNotAPassword(t *testing.T) {

	s, spy := newAccountsSteranko(map[string]string{}, hash.Plaintext{})

	// With Plaintext as the primary, the decoy hash IS its plaintext, so the comparison matches
	ok, _ := s.ComparePassword("steranko-decoy-password", s.decoyPasswordHash())
	require.True(t, ok, "precondition: the decoy must match its own plaintext")

	err := s.authenticate("nobody@nowhere.com", "steranko-decoy-password", s.userService.New())

	require.Error(t, err)
	assert.True(t, derp.IsUnauthorized(err), "got code %d", derp.ErrorCode(err))
	assert.Zero(t, spy.saves)
}

// TestAuthenticate_LoadError confirms that a failing user store is reported as a server
// error, while a NotFound wrapped by the store still counts as a missing account.
func TestAuthenticate_LoadError(t *testing.T) {

	// A store failure is a server error, and no comparison runs against it
	{
		var hashes, compares int
		s, spy := newAccountsSteranko(map[string]string{}, countingHasher{hashes: &hashes, compares: &compares})
		spy.loadErr = errors.New("connection refused")

		err := s.authenticate("michael@jackson.com", "hee-hee", s.userService.New())

		require.Error(t, err)
		assert.True(t, derp.IsInternalServerError(err), "got code %d", derp.ErrorCode(err))
		assert.False(t, derp.IsUnauthorized(err))
		assert.ErrorIs(t, err, spy.loadErr)
		assert.Equal(t, "steranko.authenticate", derp.Location(err))
		assert.Zero(t, compares)
		requireNotLeaked(t, err, "hee-hee")
	}

	// A wrapped NotFound takes the decoy path like any missing account
	{
		var hashes, compares int
		s, spy := newAccountsSteranko(map[string]string{}, countingHasher{hashes: &hashes, compares: &compares})
		spy.loadErr = derp.Wrap(derp.NotFound("store", "no such user"), "store.Load", "Unable to load user")

		err := s.authenticate("michael@jackson.com", "hee-hee", s.userService.New())

		require.Error(t, err)
		assert.True(t, derp.IsUnauthorized(err), "got code %d", derp.ErrorCode(err))
		assert.Equal(t, 1, compares, "the decoy comparison must run")
	}
}

// TestAuthenticate_PrimaryMatchIsNotSaved confirms that a password already stored by the
// primary hasher signs in without writing the account back.
func TestAuthenticate_PrimaryMatchIsNotSaved(t *testing.T) {

	stored, err := hash.BCrypt(4).HashPassword("hee-hee")
	require.NoError(t, err)

	accounts := map[string]string{"michael@jackson.com": stored}
	s, spy := newAccountsSteranko(accounts, hash.BCrypt(4), hash.Plaintext{})
	user := s.userService.New()

	require.NoError(t, s.authenticate("michael@jackson.com", "hee-hee", user))

	assert.Zero(t, spy.saves)
	assert.Equal(t, stored, accounts["michael@jackson.com"])
	assert.Equal(t, "michael@jackson.com", user.GetUsername())
	assert.Equal(t, stored, user.GetHashedPassword())
}

// TestAuthenticate_UpgradeHashFails confirms that a signin still succeeds when the primary
// hasher cannot re-hash a legacy password, and that the legacy value stays in place.
func TestAuthenticate_UpgradeHashFails(t *testing.T) {

	accounts := map[string]string{"legacy@example.com": "legacy-password"}
	s, spy := newAccountsSteranko(accounts, failHashHasher{}, hash.Plaintext{})
	user := s.userService.New()

	require.NoError(t, s.authenticate("legacy@example.com", "legacy-password", user))

	assert.Zero(t, spy.saves, "nothing is saved when the new hash could not be made")
	assert.Equal(t, "legacy-password", accounts["legacy@example.com"])
	assert.Equal(t, "legacy-password", user.GetHashedPassword())
}

// TestAuthenticate_UpgradeSaveFails confirms that a signin still succeeds when the upgraded
// hash cannot be saved, and that the failure is reported without the password in it.
func TestAuthenticate_UpgradeSaveFails(t *testing.T) {

	reporter := captureReports(t)

	accounts := map[string]string{"legacy@example.com": "legacy-password"}
	s, spy := newAccountsSteranko(accounts, hash.BCrypt(4), hash.Plaintext{})
	spy.saveErr = errors.New("disk full")
	user := s.userService.New()

	require.NoError(t, s.authenticate("legacy@example.com", "legacy-password", user))

	// The save was attempted, and the store still holds the legacy value
	assert.Equal(t, 1, spy.saves)
	assert.Equal(t, "legacy-password", accounts["legacy@example.com"])

	// The failure is reported once, naming the account and carrying neither secret
	require.Len(t, reporter.errors, 1)
	assert.ErrorIs(t, reporter.errors[0], spy.saveErr)
	assert.Equal(t, "steranko.authenticate", derp.Location(reporter.errors[0]))
	requireNotLeaked(t, reporter.errors[0], "legacy-password")
	requireNotLeaked(t, reporter.errors[0], user.GetHashedPassword())

	// The in-memory User already carries the upgraded hash
	ok, rehash := s.ComparePassword("legacy-password", user.GetHashedPassword())
	assert.True(t, ok)
	assert.False(t, rehash)
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
	seed.SetHashedPassword("plaintext-password")
	require.Nil(t, s.userService.Save(seed, "seed"))

	// Authenticate with the correct password.
	user := s.userService.New()
	require.Nil(t, s.authenticate("upgrade@example.com", "plaintext-password", user))

	// After authentication the stored password should have been upgraded to a
	// BCrypt hash (no longer equal to the plaintext value).
	reloaded := s.userService.New()
	require.Nil(t, s.userService.Load("upgrade@example.com", reloaded))
	require.NotEqual(t, "plaintext-password", reloaded.GetHashedPassword())

	// And the upgraded hash must still authenticate the original password.
	ok, update := s.ComparePassword("plaintext-password", reloaded.GetHashedPassword())
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

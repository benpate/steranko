package steranko

import (
	"testing"

	"github.com/benpate/derp"
	"github.com/benpate/steranko/plugin/hash"
	"github.com/stretchr/testify/require"
)

// FuzzAuthenticate confirms that authenticate admits a signin only when the account exists and
// its stored value matches a non-empty password, and that it refuses "" before any lookup.
func FuzzAuthenticate(f *testing.F) {

	f.Add("michael@jackson.com", "hee-hee", "hee-hee", true)
	f.Add("michael@jackson.com", "hee-hee", "hoo-hoo", true)
	f.Add("michael@jackson.com", "hee-hee", "", true)
	f.Add("blank@example.com", "", "", true)
	f.Add("blank@example.com", "", " ", true)
	f.Add("nobody@nowhere.com", "", "", false)
	f.Add("nobody@nowhere.com", "", "steranko-decoy-password", false)
	f.Add("", "", "", true)
	f.Add("", "", "x", false)
	f.Add(" ", " ", " ", true)
	f.Add("\x00", "\x00", "\x00", true)
	f.Add("\xff\xfe", "\xff", "\xff", true)

	f.Fuzz(func(t *testing.T, username string, storedHash string, password string, exists bool) {

		// Plaintext is the chain where an empty stored value matches an empty password
		accounts := map[string]string{}
		if exists {
			accounts[username] = storedHash
		}

		s, spy := newAccountsSteranko(accounts, hash.Plaintext{})
		user := s.userService.New()

		err := s.authenticate(username, password, user)

		// RULE: An empty password is refused before the user store is consulted
		if password == "" {
			require.True(t, derp.IsBadRequest(err), "empty password: got code %d", derp.ErrorCode(err))
			require.Zero(t, spy.loads, "empty password must not load the account")
			require.Zero(t, spy.saves, "empty password must not save the account")
			require.Empty(t, user.GetUsername(), "empty password must not populate the User")
			return
		}

		// A non-empty password is judged by the store and the hashers, never by the guard
		require.False(t, derp.IsBadRequest(err), "non-empty password %q tripped the guard", password)
		require.Equal(t, 1, spy.loads, "a non-empty password loads the account exactly once")

		// Admit exactly when the account exists and stores this password
		if exists && (storedHash == password) {
			require.NoError(t, err)
			require.Equal(t, username, user.GetUsername())
		} else {
			require.True(t, derp.IsUnauthorized(err), "rejected signin: got code %d", derp.ErrorCode(err))
		}

		// Plaintext re-hashes a password to itself, so no stored value ever changes
		if exists {
			require.Equal(t, map[string]string{username: storedHash}, accounts)
		} else {
			require.Empty(t, accounts, "a missing account must never be created")
		}
	})
}

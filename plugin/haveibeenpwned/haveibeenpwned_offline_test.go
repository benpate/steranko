package haveibeenpwned

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// knownHash returns the uppercase hex SHA-1 of a password, matching the encoding
// used by the Pwned Passwords range API.
func knownHash(password string) string {
	sum := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestID(t *testing.T) {
	api := &API{}
	require.Equal(t, "HaveIBeenPwned", api.ID())
}

func TestPasswordRuleDescription(t *testing.T) {
	api := &API{}
	require.Contains(t, api.PasswordRuleDescription(), "haveibeenpwned.com")
}

func TestBaseURL_Default(t *testing.T) {
	api := &API{}
	require.Equal(t, defaultBaseURL, api.baseURL())
}

func TestBaseURL_Override(t *testing.T) {
	api := &API{BaseURL: "http://example.test/range/"}
	require.Equal(t, "http://example.test/range/", api.baseURL())
}

func TestHashAndSplit(t *testing.T) {

	// "password" → uppercase SHA-1 starts with 5BAA6 (a well-known HIBP example).
	prefix, suffix := hashAndSplit("password")

	full := knownHash("password")
	require.Len(t, prefix, 5, "prefix is always the first 5 hex characters")
	require.Equal(t, full[:5], prefix)
	require.Equal(t, full[5:], suffix)
	require.Equal(t, full, prefix+suffix, "prefix+suffix must reconstruct the full hash")
	require.Equal(t, strings.ToUpper(prefix), prefix, "prefix must be uppercase")
}

func TestHashAndSplit_EmptyPassword(t *testing.T) {
	// An empty password still produces a valid 40-character SHA-1 hash.
	prefix, suffix := hashAndSplit("")
	require.Len(t, prefix, 5)
	require.Len(t, suffix, 35)
}

func TestMatchSuffix_Found(t *testing.T) {

	suffix := hashSuffix(t, "password")

	// The range body lists "SUFFIX:COUNT" lines; include our suffix with a count.
	body := bytes.NewBufferString(
		"0000000000000000000000000000000000A:1\r\n" +
			suffix + ":3730471\r\n" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\r\n",
	)

	ok, message := matchSuffix(body, suffix)
	require.False(t, ok, "a listed suffix must be reported as breached")
	require.Contains(t, message, "3730471", "the message reports the breach count")
}

func TestMatchSuffix_NotFound(t *testing.T) {

	suffix := hashSuffix(t, "an-extremely-unlikely-unique-password-value")

	body := bytes.NewBufferString(
		"0000000000000000000000000000000000A:1\r\n" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\r\n",
	)

	ok, message := matchSuffix(body, suffix)
	require.True(t, ok, "an unlisted suffix must be reported as safe")
	require.Empty(t, message)
}

func TestMatchSuffix_EmptyBody(t *testing.T) {
	ok, message := matchSuffix(bytes.NewBufferString(""), hashSuffix(t, "anything"))
	require.True(t, ok, "an empty range body means no match → safe")
	require.Empty(t, message)
}

func TestMatchSuffix_MalformedLines(t *testing.T) {
	// Lines without a colon, blank lines, and partial lines must not panic and
	// must not produce a false match.
	body := bytes.NewBufferString("\n\nnocolon\n:\nABC:\n:123\n   \n")
	ok, message := matchSuffix(body, hashSuffix(t, "anything"))
	require.True(t, ok)
	require.Empty(t, message)
}

func TestMatchSuffix_CaseSensitive(t *testing.T) {
	// HIBP returns uppercase suffixes and hashAndSplit uppercases, so a
	// lowercase line must NOT match (guards against an accidental fold).
	suffix := hashSuffix(t, "password")
	body := bytes.NewBufferString(strings.ToLower(suffix) + ":5\r\n")

	ok, _ := matchSuffix(body, suffix)
	require.True(t, ok, "a lowercase suffix line must not match an uppercase suffix")
}

func TestValidatePassword_FailsOpenOnUnreachableHost(t *testing.T) {
	// Pointing at a host that cannot connect must fail OPEN (allow the password)
	// rather than block a signin on a third-party outage. Using a reserved TEST-NET
	// address (RFC 5737) avoids any real network dependency.
	api := &API{BaseURL: "http://192.0.2.1:1/range/"}

	ok, message := api.ValidatePassword("password")
	require.True(t, ok, "an unreachable HIBP endpoint must fail open")
	require.Empty(t, message)
}

// hashSuffix returns the range-API suffix (hash minus the 5-char prefix) for a
// password, so tests can build response bodies that do or do not contain it.
func hashSuffix(t *testing.T, password string) string {
	t.Helper()
	_, suffix := hashAndSplit(password)
	return suffix
}

// FuzzMatchSuffix throws arbitrary range-response bodies and suffixes at the
// parser to confirm it never panics on untrusted input from the remote API.
func FuzzMatchSuffix(f *testing.F) {

	f.Add("ABCDE:1\r\nFGHIJ:2\r\n", "ABCDE")
	f.Add("", "ABCDE")
	f.Add(":\n::\n", "")
	f.Add("nocolon", "X")
	f.Add("\x00\x01:\xff", "\x00")

	f.Fuzz(func(t *testing.T, body string, suffix string) {
		// The only invariant: parsing arbitrary bytes never panics, and a match
		// (OK == false) only ever happens with a non-empty message.
		if ok, message := matchSuffix(bytes.NewBufferString(body), suffix); !ok {
			require.NotEmpty(t, message, "a breach match must carry a message")
		}
	})
}

// FuzzHashAndSplit confirms the hash/split step never panics and always returns
// a 5-character prefix plus a 35-character suffix for any input.
func FuzzHashAndSplit(f *testing.F) {

	f.Add("")
	f.Add("password")
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("x", 10000))

	f.Fuzz(func(t *testing.T, password string) {
		prefix, suffix := hashAndSplit(password)
		require.Len(t, prefix, 5)
		require.Len(t, suffix, 35)
	})
}

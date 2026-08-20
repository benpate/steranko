// Package haveibeenpwned provides a Steranko password rule that rejects
// passwords found in known data breaches, via the HaveIBeenPwned.com API.
package haveibeenpwned

import (
	"bufio"
	"bytes"
	"crypto/sha1" // #nosec G505 -- SHA-1 is fixed by the Pwned Passwords range API, not a choice
	"encoding/hex"
	"strings"

	"github.com/benpate/derp"
	"github.com/benpate/remote"
)

// defaultBaseURL is the production HaveIBeenPwned range endpoint. The 5-character
// SHA-1 prefix is appended to this value.
const defaultBaseURL = "https://api.pwnedpasswords.com/range/"

// maxResponseSize bounds the breach response. A range query returns only a few KB, so this is
// far above any legitimate answer while still protecting against a hostile or malfunctioning
// server. It caps BOTH the download and the line scanner, so the two cannot disagree.
const maxResponseSize = 1 << 20 // 1MB

// API represents the HaveIBeenPwned.com api, and manages all remote calls to this API to check for passwords that have appeared in previous data breaches.
type API struct {
	// BaseURL overrides the range endpoint. The zero value uses the production
	// API; tests set it to a local server. It must end with a trailing slash.
	BaseURL string
}

// ID returns a string that uniquely identifies this plugin.
func (api *API) ID() string {
	return "HaveIBeenPwned"
}

// PasswordRuleDescription returns a human-friendly description of the password rule.
func (api *API) PasswordRuleDescription() string {
	return "Password can not appear on previously breached websites.  Visit https://haveibeenpwned.com for more info."
}

// ValidatePassword verifies that a password matches a rule, or returns a human-friendly error message explaining the problem.
func (api *API) ValidatePassword(password string) (OK bool, message string) {

	// Hash the password and split it for the k-anonymity range query: only the
	// 5-character prefix is ever sent; the suffix is matched locally.
	prefix, suffix := hashAndSplit(password)

	// Send the request to the remote API. The range endpoint returns only a few
	// KB, so cap the response well below remote's 1GB default to bound memory
	// against a hostile or malfunctioning server.
	var response bytes.Buffer

	transaction := remote.Get(api.baseURL() + prefix).
		MaxResponseSize(maxResponseSize).
		Result(&response)

	// Fail open: if the remote service is unreachable (or the response exceeds
	// the size cap) we cannot check for breaches, so we allow the password
	// rather than block all signins on a third-party outage.
	if err := transaction.Send(); err != nil {
		return true, ""
	}

	return matchSuffix(&response, suffix)
}

// baseURL returns the configured range endpoint, defaulting to the production API.
func (api *API) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}

	return defaultBaseURL
}

// hashAndSplit returns the uppercase hex SHA-1 of the password, split into the
// 5-character range prefix and the remaining suffix used for local matching.
func hashAndSplit(password string) (prefix string, suffix string) {
	// #nosec G401 -- The k-anonymity range API is defined in terms of SHA-1: the server indexes
	// by the first 5 hex characters of the SHA-1 digest, so no other algorithm can query it.
	// Nothing here is stored or trusted as a credential; the digest is a lookup key.
	hashedBytes := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(hashedBytes[:]))

	return encoded[:5], encoded[5:]
}

// matchSuffix scans a Pwned Passwords range response (lines of "SUFFIX:COUNT")
// for the given hash suffix, returning whether the password is safe to use.
func matchSuffix(response *bytes.Buffer, suffix string) (OK bool, message string) {

	scanner := bufio.NewScanner(response)

	// Size the scanner to the same 1MB cap that bounds the response. At the default 64KB line
	// limit, a single over-long line ends the scan early with no error visible here, so every
	// suffix after it goes uncompared and a breached password is reported as safe.
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxResponseSize)

	for scanner.Scan() {
		line := scanner.Text()
		usedSuffix, useCount, _ := strings.Cut(line, ":") // nolint:scopeguard - readability

		if usedSuffix == suffix {
			return false, "Password has been used " + useCount + " times before on hacked websites.  Visit https://haveibeenpwned.com for more info."
		}
	}

	// A scan that ended early has not cleared this password, but it has not condemned it either.
	// Report the same fail-open answer as an unreachable API: a partial answer must not become a
	// rejection, and the incomplete read is surfaced to the caller's logs rather than swallowed.
	if err := scanner.Err(); err != nil {
		derp.Report(derp.Wrap(err, "steranko.plugin.haveibeenpwned.matchSuffix", "Unable to read the full breach response; password was NOT checked"))
	}

	return true, ""
}

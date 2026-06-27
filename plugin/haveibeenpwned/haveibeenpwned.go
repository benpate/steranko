// Package haveibeenpwned provides a Steranko password rule that rejects
// passwords found in known data breaches, via the HaveIBeenPwned.com API.
package haveibeenpwned

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/benpate/remote"
)

// defaultBaseURL is the production HaveIBeenPwned range endpoint. The 5-character
// SHA-1 prefix is appended to this value.
const defaultBaseURL = "https://api.pwnedpasswords.com/range/"

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
		MaxResponseSize(1 << 20). // 1MB
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
	hashedBytes := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(hashedBytes[:]))

	return encoded[:5], encoded[5:]
}

// matchSuffix scans a Pwned Passwords range response (lines of "SUFFIX:COUNT")
// for the given hash suffix, returning whether the password is safe to use.
func matchSuffix(response *bytes.Buffer, suffix string) (OK bool, message string) {

	for scanner := bufio.NewScanner(response); scanner.Scan(); {
		line := scanner.Text()
		usedSuffix, useCount, _ := strings.Cut(line, ":") // nolint:scopeguard - readability

		if usedSuffix == suffix {
			return false, "Password has been used " + useCount + " times before on hacked websites.  Visit https://haveibeenpwned.com for more info."
		}
	}

	return true, ""
}

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

// API represents the HaveIBeenPwned.com api, and manages all remote calls to this API to check for passwords that have appeared in previous data breaches.
type API struct{}

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

	// Use SHA1 and Base64 encoding to hash the password.
	hashedBytes := sha1.Sum([]byte(password))
	encoded := hex.EncodeToString(hashedBytes[:])
	encoded = strings.ToUpper(encoded)

	// Split the encoded value into prefix and suffix
	prefix := encoded[:5]
	suffix := encoded[5:] //nolint:scopeguard

	// Send the request to the remote API. The range endpoint returns only a few
	// KB, so cap the response well below remote's 1GB default to bound memory
	// against a hostile or malfunctioning server.
	var response bytes.Buffer

	transaction := remote.Get("https://api.pwnedpasswords.com/range/" + prefix).
		MaxResponseSize(1 << 20). // 1MB
		Result(&response)

	// Fail open: if the remote service is unreachable (or the response exceeds
	// the size cap) we cannot check for breaches, so we allow the password
	// rather than block all signins on a third-party outage.
	if err := transaction.Send(); err != nil {
		return true, ""
	}

	for scanner := bufio.NewScanner(&response); scanner.Scan(); {
		line := scanner.Text()
		usedSuffix, useCount, _ := strings.Cut(line, ":") // nolint:scopeguard - readability

		if usedSuffix == suffix {
			return false, "Password has been used " + useCount + " times before on hacked websites.  Visit https://haveibeenpwned.com for more info."
		}
	}

	return true, ""
}

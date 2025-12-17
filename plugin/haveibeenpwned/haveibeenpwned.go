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

// PasswordRuleDescription returns a localized, human-friendly description of the password rule.
func (api *API) PasswordRuleDescription(language string) string {
	return "Password can not appear on previously breached websites.  Visit https://haveibeenpwned.com for more info."
}

// ValidatePassword verifies that a password matches a rule, or returns a localized, human-friendly error message explaining the problem.
func (api *API) ValidatePassword(password string, language string) (OK bool, message string) {

	// Use SHA1 and Base64 encoding to hash the password.
	hashedBytes := sha1.Sum([]byte(password))
	encoded := hex.EncodeToString(hashedBytes[:])
	encoded = strings.ToUpper(encoded)

	// Split the encoded value into prefix and suffix
	prefix := encoded[:5]
	suffix := encoded[5:] //nolint:scopeguard

	// Send the request to the remote API.  If this breaks, then we'll just get no breach reports and will return 'success'.
	var response bytes.Buffer

	transaction := remote.Get("https://api.pwnedpasswords.com/range/" + prefix).
		Result(&response)

	if err := transaction.Send(); err != nil {

		// Error connecting to the remote service.
		// Swallow this for now, because we don't have a better way
		// of reporting the error..
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

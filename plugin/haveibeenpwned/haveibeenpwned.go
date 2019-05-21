package haveibeenpwned

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
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
	h := sha1.New()
	hashedBytes := h.Sum([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashedBytes)

	// Split the encoded value into prefix and suffix
	prefix := encoded[:5]
	suffix := encoded[6:]

	// Send the request to the remote API.  If this breaks, then we'll just get no breach reports and will return 'success'.
	var response bytes.Buffer

	remote.Get("https://api.pwnedpasswords.com/range"+prefix).Response(&response, nil).Send()
	// TODO: we're swallowing errors (for now)

	scanner := bufio.NewScanner(&response)

	for scanner.Scan() {
		line := scanner.Text()
		values := strings.Split(line, ":")

		if values[0] == suffix {
			return false, "Password has been used " + values[1] + " times before on hacked websites.  Visit https://haveibeenpwned.com for more info."
		}
	}

	return true, ""
}

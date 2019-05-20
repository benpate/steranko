package steranko

import (
	"encoding/json"
	"net/http"
)

// Handler Functions for creating new accounts.

// HandleAddSignupData implements the http.HandlerFunc signature, and is
// used to add browser interaction data to the signup process.  This data
// is used by Steranko to determine if the browser is controlled by a
// human or by a bot.
func (s *Steranko) HandleAddSignupData(w http.ResponseWriter, r *http.Request) {

}

// HandleCreateUserAccount implements the http.HandlerFunc signature, and is
// used to create new user accounts.
func (s *Steranko) HandleCreateUserAccount(w http.ResponseWriter, r *http.Request) {

	result := ""

	if j, err := json.Marshal(result); err == nil {
		w.Write(j)
	}
}

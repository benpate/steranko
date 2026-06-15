package steranko

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/benpate/derp"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestPostPasswordToken_Success(t *testing.T) {

	s := getTestSteranko()

	form := url.Values{}
	form.Set("username", "michael@jackson.com")

	require.Nil(t, s.PostPasswordToken(echoContext(t, formRequest(form))))
}

// TestPostPasswordToken_UnknownUser confirms that an unknown account returns a
// generic "Unauthorized" error rather than revealing that the user is missing.
func TestPostPasswordToken_UnknownUser(t *testing.T) {

	s := getTestSteranko()

	form := url.Values{}
	form.Set("username", "nobody@nowhere.com")

	err := s.PostPasswordToken(echoContext(t, formRequest(form)))

	require.NotNil(t, err)
	require.True(t, derp.IsUnauthorized(err), "missing accounts must not be distinguishable from auth failures")
}

// TestPostPasswordToken_ResetError confirms that an error from the underlying
// RequestPasswordReset call is propagated.
func TestPostPasswordToken_ResetError(t *testing.T) {

	s := getTestSteranko()
	s.userService = resetErrorUserService{UserService: s.userService}

	form := url.Values{}
	form.Set("username", "michael@jackson.com")

	err := s.PostPasswordToken(echoContext(t, formRequest(form)))
	require.NotNil(t, err)
}

// TestPostPasswordToken_BadRequest confirms a malformed body fails to bind.
func TestPostPasswordToken_BadRequest(t *testing.T) {

	s := getTestSteranko()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad-json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	require.NotNil(t, s.PostPasswordToken(echoContext(t, req)))
}

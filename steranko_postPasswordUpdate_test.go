package steranko

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestPostPasswordUpdate_Fail(t *testing.T) {

	s := getTestSteranko()

	// A new password that violates the schema (too short) must be rejected.
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("oldPassword", "whitehouse")
	transaction.Set("newPassword", "too-short")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	c := e.NewContext(req, httptest.NewRecorder())

	require.NotNil(t, s.PostPasswordUpdate(c))

	// RULE: a rejected update must leave the stored password untouched.
	user := s.userService.New()
	require.NoError(t, s.userService.Load("andrew@jackson.com", user))
	require.Equal(t, "whitehouse", user.GetPassword(), "password must not change when the update is rejected")
}

func TestPostPasswordUpdate_Success(t *testing.T) {

	s := getTestSteranko()

	// A valid new password must be accepted and persisted.
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("oldPassword", "whitehouse")
	transaction.Set("newPassword", "valid-password")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	c := e.NewContext(req, httptest.NewRecorder())

	require.Nil(t, s.PostPasswordUpdate(c))

	// The stored password must now be the new value. (This Steranko uses the
	// Plaintext hasher, so the stored ciphertext equals the plaintext.)
	user := s.userService.New()
	require.NoError(t, s.userService.Load("andrew@jackson.com", user))
	require.Equal(t, "valid-password", user.GetPassword(), "password must be updated on success")
}

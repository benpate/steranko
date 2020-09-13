package steranko

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo"
	"github.com/stretchr/testify/require"
)

func TestPostPasswordUpdate_Fail(t *testing.T) {

	s := getTestSteranko()

	// Mock Form Body
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("oldPassword", "whitehouse")
	transaction.Set("newPassword", "too-short")

	// Create New HTTP Request
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Assertions
	require.NotNil(t, s.PostPasswordUpdate(c))
	// require.Equal(t, http.StatusBadRequest, rec.Code)

	// Verify Password NOT changed
	s.UserService.Load("andrew@jackson.com")
}

func TestPostPasswordUpdate_Success(t *testing.T) {

	s := getTestSteranko()

	// Mock Form Body
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("oldPassword", "whitehouse")
	transaction.Set("newPassword", "valid-password")

	// Create New HTTP Request
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Assertions
	require.Nil(t, s.PostPasswordUpdate(c))
	require.Equal(t, http.StatusOK, rec.Code)

	// Verify Password NOT changed
	s.UserService.Load("andrew@jackson.com")

}

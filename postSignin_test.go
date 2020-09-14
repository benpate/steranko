package steranko

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostSignin_Header(t *testing.T) {

	s := getTestSteranko()

	// Mock Form Body
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("password", "whitehouse")

	// Create New HTTP Request
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Assertions
	require.Nil(t, s.PostSignin(c))
	require.Equal(t, http.StatusOK, rec.Code)

	token := rec.Header().Get("Authentication")
	require.NotEqual(t, "", token)
	// t.Log(token)
}

func TestPostSignin_Cookie(t *testing.T) {

	s := getTestSteranko()
	s.Config.Token = "cookie:Authentication"

	// Mock Form Body
	transaction := make(url.Values)
	transaction.Set("username", "andrew@jackson.com")
	transaction.Set("password", "whitehouse")

	// Create New HTTP Request
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(transaction.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Assertions
	require.Nil(t, s.PostSignin(c))
	require.Equal(t, http.StatusOK, rec.Code)

	token := rec.Result().Header["Set-Cookie"]
	assert.NotEqual(t, "", token)
	// t.Log(token)
}

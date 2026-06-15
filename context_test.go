package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {

	e := echo.New()
	s := getTestSteranko()

	req, _ := http.NewRequest("GET", "test.com", nil)
	req.AddCookie(&http.Cookie{
		Name:  "Authorization",
		Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
	})

	sterankoContext := Context{
		Context:  e.NewContext(req, httptest.NewRecorder()),
		steranko: s,
	}

	auth, err := sterankoContext.Authorization()

	require.Nil(t, err)
	require.NotNil(t, auth)

	authMap := auth.(jwt.MapClaims)
	require.Equal(t, true, authMap["admin"])
	require.Equal(t, "John Doe", authMap["name"])
	require.Equal(t, "1234567890", authMap["sub"])
}

// TestContext_Cached confirms that Authorization caches the parsed claims and
// returns the cached value without re-parsing.
func TestContext_Cached(t *testing.T) {

	cached := jwt.MapClaims{"username": "cached@example.com"}

	// Pre-populate the cache. The request has no token, so if the cache were
	// ignored, parsing would fail.
	req := httptest.NewRequest("GET", "/", nil)
	sterankoContext := Context{
		Context:  echoContext(t, req),
		steranko: getTestSteranko(),
		claims:   cached,
	}

	auth, err := sterankoContext.Authorization()

	require.Nil(t, err)
	require.Equal(t, cached, auth)
}

// TestContext_Error confirms that a parsing error is wrapped and returned, and
// that no claims are produced.
func TestContext_Error(t *testing.T) {

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "not-a-valid-token"})

	sterankoContext := Context{
		Context:  echoContext(t, req),
		steranko: getTestSteranko(),
	}

	auth, err := sterankoContext.Authorization()

	require.NotNil(t, err)
	require.Nil(t, auth)
}

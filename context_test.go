package steranko

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
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
	t.Log(auth)

	authMap := auth.(jwt.MapClaims)
	require.Equal(t, true, authMap["admin"])
	require.Equal(t, "John Doe", authMap["name"])
	require.Equal(t, "1234567890", authMap["sub"])
}

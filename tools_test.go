package steranko

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/benpate/rosetta/schema"
)

func TestAuthenticate(t *testing.T) {

	s := getTestSteranko()

	{
		// Test successful signin
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hee-hee", user)
		require.Nil(t, err)
		require.NotNil(t, user)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		// Test bad password
		user := s.userService.New()
		err := s.authenticate("michael@jackson.com", "hoo-hoo", user)
		require.NotNil(t, err)
		require.Equal(t, "michael@jackson.com", user.GetUsername())
		require.Equal(t, "hee-hee", user.GetPassword())
	}

	{
		// Test missing user
		user := s.userService.New()
		err := s.authenticate("kendall@jackson.com", "chardonay", user)
		require.NotNil(t, err)
		require.Equal(t, "", user.GetUsername())
		require.Equal(t, "", user.GetPassword())
	}
}

func TestValidatePassword(t *testing.T) {

	s := getTestSteranko()

	require.NotNil(t, s.ValidatePassword("too-short"))
	require.NotNil(t, s.ValidatePassword("this-password-is-way-too-long"))
	require.Nil(t, s.ValidatePassword("valid-password"))
}

func TestPasswordSchema(t *testing.T) {

	var input schema.Schema

	err := json.Unmarshal([]byte(`{"type":"string", "minLength":0, "maxLength":20}`), &input)
	require.Nil(t, err)

	s := New(getTestUserService(), getTestKeyService(), WithPasswordSchema(input))
	sch := s.passwordSchema

	require.NotNil(t, sch)
	require.IsType(t, schema.String{}, sch.Element)
	require.Equal(t, 0, sch.Element.(schema.String).MinLength)
	require.Equal(t, 20, sch.Element.(schema.String).MaxLength)
}

func TestJWTValidMethods(t *testing.T) {

	// JWTValidMethods restricts the parser to a fixed allow-list of symmetric
	// HMAC methods. We confirm the allow-list by parsing tokens signed with
	// each method.
	option := JWTValidMethods()

	parser := jwt.NewParser(option)
	key := []byte("secret")

	sign := func(method jwt.SigningMethod) string {
		token := jwt.NewWithClaims(method, jwt.MapClaims{"sub": "1"})
		signed, err := token.SignedString(key)
		require.Nil(t, err)
		return signed
	}

	// HS256, HS384, and HS512 are all accepted.
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		_, err := parser.Parse(sign(method), func(*jwt.Token) (any, error) { return key, nil })
		require.Nil(t, err, "method %s should be allowed", method.Alg())
	}

	// An unapproved method (e.g. "none") must be rejected.
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "1"})
	noneString, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.Nil(t, err)
	_, err = parser.Parse(noneString, func(*jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil })
	require.NotNil(t, err, "the 'none' algorithm must be rejected by the allow-list")
}

func TestCookieName(t *testing.T) {

	// Non-TLS requests use the plain "Authorization" cookie name.
	require.Equal(t, "Authorization", cookieName(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)))

	// TLS requests use the host-locked "__Host-Authorization" cookie name.
	require.Equal(t, "__Host-Authorization", cookieName(httptest.NewRequest(http.MethodGet, "https://example.com/", nil)))
}

func TestIsTLS(t *testing.T) {

	require.False(t, isTLS(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)))
	require.True(t, isTLS(httptest.NewRequest(http.MethodGet, "https://example.com/", nil)))
}

func TestCopyCookie(t *testing.T) {

	// copyCookie must produce a value-equal copy of every relevant field.
	original := &http.Cookie{
		Name:     "Authorization",
		Value:    "token-value",
		MaxAge:   1234,
		Domain:   "example.com",
		Path:     "/path",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	clone := copyCookie(original)

	require.Equal(t, original.Name, clone.Name)
	require.Equal(t, original.Value, clone.Value)
	require.Equal(t, original.MaxAge, clone.MaxAge)
	require.Equal(t, original.Domain, clone.Domain)
	require.Equal(t, original.Path, clone.Path)
	require.Equal(t, original.HttpOnly, clone.HttpOnly)
	require.Equal(t, original.Secure, clone.Secure)
	require.Equal(t, original.SameSite, clone.SameSite)
}

func TestPushCookie(t *testing.T) {

	// When an existing cookie is present, pushCookie should move it to a
	// "-backup" cookie before writing the new value.
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "Authorization", Value: "original-token"})
		ctx, rec := echoContextWithRecorder(t, req)

		pushCookie(ctx, http.Cookie{Name: "Authorization", Value: "new-token"})

		cookies := rec.Result().Cookies()

		authCookie := findCookie(t, cookies, "Authorization")
		require.NotNil(t, authCookie)
		require.Equal(t, "new-token", authCookie.Value)

		backupCookie := findCookie(t, cookies, "Authorization-backup")
		require.NotNil(t, backupCookie)
		require.Equal(t, "original-token", backupCookie.Value)
	}

	// When there is no existing cookie, only the new cookie is written (no
	// backup is created).
	{
		ctx, rec := echoContextWithRecorder(t, httptest.NewRequest(http.MethodGet, "/", nil))

		pushCookie(ctx, http.Cookie{Name: "Authorization", Value: "new-token"})

		cookies := rec.Result().Cookies()
		require.Equal(t, "new-token", findCookie(t, cookies, "Authorization").Value)
		require.Nil(t, findCookie(t, cookies, "Authorization-backup"))
	}
}

func TestSleepRandom(t *testing.T) {

	// sleepRandom must always sleep at least the minimum duration, and the
	// degenerate min==max case must not panic (rand.Intn requires a positive
	// argument, which the +1 guarantees).
	require.NotPanics(t, func() {
		sleepRandom(1, 1)
	})

	start := time.Now()
	sleepRandom(10, 20)
	require.GreaterOrEqual(t, time.Since(start), 10*time.Millisecond)
}

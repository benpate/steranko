package steranko

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// Context extends the echo context with an authenticated JWT Token.
type Context struct {
	echo.Context
	Token *jwt.Token
}

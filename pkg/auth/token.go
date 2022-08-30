package auth

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const SigningKey = "secret"

// JwtCustomClaims are custom claims extending default ones.
// See https://github.com/golang-jwt/jwt for more examples
type JwtCustomClaims struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func DefaultMiddleware() echo.MiddlewareFunc {
	return middleware.JWTWithConfig(
		middleware.JWTConfig{
			Claims:     &JwtCustomClaims{},
			SigningKey: []byte("secret")})
}

package capture

import (
	"kpture/pkg/auth"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type Captureservice struct{}

func NewCaptureservice(e *echo.Echo, midlewares ...echo.MiddlewareFunc) {
	captureGroup := e.Group("/restricted")
	for _, md := range midlewares {
		captureGroup.Use(md)
	}
	c := &Captureservice{}
	captureGroup.GET("", c.restricted)
}

func (k *Captureservice) restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.JwtCustomClaims)
	name := claims.Name
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

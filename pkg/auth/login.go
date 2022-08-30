package auth

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func (a *AuthService) login(c echo.Context) error {
	var (
		body  User
		found User
	)

	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	res := a.DB.First(&found, "username = ?", body.Username)

	if res.Error != nil {
		return c.JSON(http.StatusInternalServerError, res.Error)
	}
	if res.RowsAffected == 0 {
		return c.JSON(http.StatusNotFound, nil)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(found.Password), []byte(body.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	// Create token with claims
	if token, err := found.defaultToken(); err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	} else {
		return c.JSON(http.StatusOK, echo.Map{"token": token})
	}

}

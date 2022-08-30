package auth

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func (a *AuthService) signup(c echo.Context) error {
	// Parse and decode the request body into a new `Credentials` instance
	var (
		creds   User
		exist   bool
		genUUID string
	)

	if err := c.Bind(&creds); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	genUUID = uuid.NewString()
	if err := a.DB.Model(&User{}).
		Select("count(*) > 0").
		Where("UUID = ?", genUUID).
		Find(&exist).Error; err != nil {
		logrus.Error("already exist")
	}

	// Salt and hash the password using the bcrypt algorithm
	// The second argument is the cost of hashing, which we arbitrarily set as 8 (this value can be more or less, depending on the computing power you wish to utilize)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
	if err != nil {
		c.Response().Writer.WriteHeader(http.StatusInternalServerError)
		if _, errw := c.Response().Writer.Write([]byte(err.Error())); errw != nil {
			logrus.Error(errw)
		}
	}

	res := a.DB.Create(&User{Username: creds.Username, Password: string(hashedPassword), UUID: genUUID})
	if res.Error != nil {
		c.Response().Writer.WriteHeader(http.StatusInternalServerError)
		if _, errw := c.Response().Writer.Write([]byte(res.Error.Error())); errw != nil {
			logrus.Error(errw)
		}
	}

	return nil
	// We reach this point if the credentials we correctly stored in the database, and the default status of 200 is sent back
}

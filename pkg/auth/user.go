package auth

import (
	"time"

	"github.com/golang-jwt/jwt"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UUID     string `gorm:"unique"`
	Password string `json:"password"`
	Username string `json:"username" gorm:"unique"`
}

func (u User) defaultClaim() *JwtCustomClaims {
	return &JwtCustomClaims{u.Username, u.UUID, false, jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Hour * 72).Unix()}}
}

func (u User) defaultToken() (string, error) {
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, u.defaultClaim())

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(SigningKey))
	if err != nil {
		return "", err
	}
	return t, nil
}

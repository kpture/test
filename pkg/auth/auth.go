package auth

import (
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type AuthService struct {
	*gorm.DB
}

func NewAuthService(e *echo.Echo, db *gorm.DB) {
	// Migrate user the schema
	if err := db.AutoMigrate(&User{}); err != nil {
		panic(err)
	}

	auth := AuthService{DB: db}
	// Login route
	e.POST("/login", auth.login)
	e.POST("/signup", auth.signup)

}

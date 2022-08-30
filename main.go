package main

import (
	"kpture/pkg/auth"
	"kpture/pkg/capture"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {

	db, err := gorm.Open(sqlite.Open("user.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	auth.NewAuthService(e, db)
	capture.NewCaptureservice(e, auth.DefaultMiddleware())

	e.Logger.Fatal(e.Start(":1323"))
}

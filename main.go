package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UUID     string `gorm:"unique"`
	Password string `json:"password"`
	Username string `json:"username" gorm:"unique"`
}

// jwtCustomClaims are custom claims extending default ones.
// See https://github.com/golang-jwt/jwt for more examples
type jwtCustomClaims struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

type HttpServer struct {
	*gorm.DB
}

func (s *HttpServer) login(c echo.Context) error {
	creds := &User{}
	if err := c.Bind(creds); err != nil {
		return c.JSON(http.StatusBadRequest, nil)
	}

	found := &User{}
	var exist bool
	s.DB.First(&found, "username = ?", creds.Username)
	err := s.DB.Model(&User{}).
		Select("username = ?", creds.Username).
		Find(&exist).Error
	if err != nil {
		logrus.Error(err)
	}
	if !exist {
		logrus.Error("user does not exist")
	}

	fmt.Println("PASWORD")
	fmt.Println(found.Password)

	err = bcrypt.CompareHashAndPassword([]byte(found.Password), []byte(creds.Password))
	if err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid password")
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		creds.Username,
		found.UUID,
		true,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
		"user":  found.Username,
		"uuid":  found.UUID,
	})
}

func (s *HttpServer) signup(c echo.Context) error {
	// Parse and decode the request body into a new `Credentials` instance
	creds := &User{}

	if err := c.Bind(creds); err != nil {
		return c.JSON(http.StatusBadRequest, nil)
	}
	newUuid := uuid.NewString()
	var exist bool
	err := s.DB.Model(&User{}).
		Select("count(*) > 0").
		Where("UUID = ?", newUuid).
		Find(&exist).Error

	if exist || err != nil {
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
	res := s.DB.Create(&User{Username: creds.Username, Password: string(hashedPassword), UUID: newUuid})
	if res.Error != nil {
		c.Response().Writer.WriteHeader(http.StatusInternalServerError)
		if _, errw := c.Response().Writer.Write([]byte(res.Error.Error())); errw != nil {
			logrus.Error(errw)
		}
	}

	return nil
	// We reach this point if the credentials we correctly stored in the database, and the default status of 200 is sent back
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {

	db, err := gorm.Open(sqlite.Open("user.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	if err := db.AutoMigrate(&User{}); err != nil {
		panic(err)
	}

	server := HttpServer{DB: db}

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Login route
	e.POST("/login", server.login)
	e.POST("/signup", server.signup)

	// Unauthenticated route
	e.GET("/", accessible)

	// Restricted group
	r := e.Group("/restricted")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}
	r.Use(middleware.JWTWithConfig(config))
	r.GET("", restricted)

	e.Logger.Fatal(e.Start(":1323"))
}

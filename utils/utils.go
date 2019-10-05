package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/imranismail/cloudcreds/templates"
	"github.com/labstack/echo/v4"
)

func NewEcho() *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = httpErrorHandler

	return e
}

func SecureRandString(s int) string {
	b := make([]byte, s)
	_, err := rand.Read(b)

	if err != nil {
		log.Fatalln(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

func httpErrorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError

	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
	}

	msg := templates.Message{
		Content: fmt.Sprintf("an error occurred: %v", err),
		Context: "Error",
		Color:   "red",
	}

	c.HTML(code, msg.Render())

	c.Logger().Error(err)
}

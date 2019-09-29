package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"

	"github.com/labstack/echo"
)

func NewEcho(serverType string) *echo.Echo {
	tplGlob := fmt.Sprintf("%s/templates/*.html", serverType)

	e := echo.New()
	e.HTTPErrorHandler = httpErrorHandler
	e.Renderer = &templateRenderer{
		templates: template.Must(template.ParseGlob(tplGlob)),
	}

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

	c.Render(code, "message.html", map[string]interface{}{
		"message": fmt.Sprintf("an error occurred: %v", err),
		"context": "Error",
		"color":   "red",
	})

	c.Logger().Error(err)
}

type templateRenderer struct {
	templates *template.Template
}

func (t *templateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

package utils

import (
	"net/http"
	"fmt"
	"github.com/labstack/echo"
)

func HTTPErrorHandler(err error, c echo.Context) {
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
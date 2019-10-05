package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/imranismail/cloudcreds/utils"
	"github.com/labstack/echo/v4"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/viper"
)

func serverAdr() string {
	clientURL, err := url.Parse(viper.GetString("client.url"))

	if err != nil {
		log.Fatalln(err)
	}

	return fmt.Sprintf("%v:%v", clientURL.Hostname(), clientURL.Port())
}

func Console() {
	err := open.Run(viper.GetString("client.server_url"))

	if err != nil {
		log.Fatalln(err)
	}
}

func Login() {
	ctx, cancel := context.WithCancel(context.Background())

	cli := utils.NewEcho("client")
	cli.HideBanner = true
	cli.HidePort = true
	cli.Debug = viper.GetBool("debug")

	srvURL, err := url.Parse(viper.GetString("client.server_url"))

	if err != nil {
		log.Fatalln(err)
	}

	qry := srvURL.Query()
	qry.Set("redirect_uri", viper.GetString("client.url"))

	srvURL.RawQuery = qry.Encode()

	err = open.Run(srvURL.String())

	if err != nil {
		log.Fatalln(err)
	}

	cli.GET("/", func(c echo.Context) error {
		defer cancel()

		rawCreds := c.QueryParam("cloudcreds")
		rawByte, err := base64.URLEncoding.DecodeString(rawCreds)

		if err != nil {
			return err
		}

		creds := strings.Split(string(rawByte), ":")

		if len(creds) < 3 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid credentials given from server")
		}

		fmt.Printf("AWS_ACCESS_KEY_ID=%v\n", creds[0])
		fmt.Printf("AWS_SECRET_ACCESS_KEY=%v\n", creds[1])
		fmt.Printf("AWS_SESSION_TOKEN=%v\n", creds[2])

		return c.Render(http.StatusOK, "message.html", map[string]interface{}{
			"message": "You may now close this window and use the temporary credentials",
			"context": "Success",
			"color":   "green",
		})
	})

	go func() {
		cli.Start(serverAdr())
	}()
	<-ctx.Done()

	cli.Shutdown(ctx)
}

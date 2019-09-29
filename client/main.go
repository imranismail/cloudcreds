package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/imranismail/cloudcreds/utils"
	"github.com/labstack/echo"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/viper"
)

var cfg *Config

type Config struct {
	Debug     bool   `mapstructure:"debug"`
	URL       string `mapstructure:"url"`
	ServerURL string `mapstructure:"server_url"`
}

func (c *Config) Addr() string {
	clientURL, err := url.Parse(c.URL)

	if err != nil {
		log.Fatalln(err)
	}

	return fmt.Sprintf("%v:%v", clientURL.Hostname(), clientURL.Port())
}

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigName("client")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./.cloudcreds")
	viper.SetDefault("debug", false)
	viper.ReadInConfig()
	viper.AutomaticEnv()

	err := viper.Unmarshal(&cfg)

	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	e := utils.NewEcho("client")
	e.HideBanner = true
	e.HidePort = true
	e.Debug = cfg.Debug

	serverURL, err := url.Parse(cfg.ServerURL)

	if err != nil {
		log.Fatalln(err)
	}

	q := serverURL.Query()
	q.Set("redirect_uri", cfg.URL)

	serverURL.RawQuery = q.Encode()

	err = open.Run(serverURL.String())

	if err != nil {
		log.Fatalln(err)
	}

	e.GET("/", func(c echo.Context) error {
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
		e.Start(cfg.Addr())
	}()
	<-ctx.Done()

	e.Shutdown(ctx)
}

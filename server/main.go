package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/imranismail/cloudcreds/server/session"
	"github.com/imranismail/cloudcreds/utils"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"

	admin "google.golang.org/api/admin/directory/v1"
)

type Role struct {
	Value string `json:"value"`
}

type Schema struct {
	Roles []Role `json:"role"`
}

type Claims struct {
	Email string `json:"email"`
}

type RolesByAccount map[string][]arn.ARN

func (rba *RolesByAccount) Has(arnString string) bool {
	for _, arns := range *rba {
		for _, arn := range arns {
			if arn.String() == arnString {
				return true
			}
		}
	}

	return false
}

type State struct {
	RolesByAccount RolesByAccount
	IDToken        string
	CSRFToken      string
	Email          string
	Duration       int64
}

type NewSessionData struct {
	RolesByAccount RolesByAccount
	StateData      string
}

type Config struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Port         int      `mapstructure:"port"`
	Hostname     string   `mapstructure:"hostname"`
	URL          string   `mapstructure:"url"`
	HostedDomain string   `mapstructure:"hosted_domain"`
	Scopes       []string `mapstructure:"scopes"`
	IssuerURL    string   `mapstructure:"issuer_url"`
	Debug        bool     `mapstructure:"debug"`
	SessionKey   string   `mapstructure:"session_key"`
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Hostname, c.Port)
}

var cfg *Config
var vrf *oidc.IDTokenVerifier
var oa *oauth2.Config
var ctx context.Context

func init() {
	ctx = context.Background()

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigName("server")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./.cloudcreds")
	viper.SetDefault("port", 1337)
	viper.SetDefault("hostname", "127.0.0.1")
	viper.SetDefault("url", "http://127.0.0.1:1337")
	viper.SetDefault("debug", false)
	viper.SetDefault("session_key", "please-set-this-to-a-high-entropy-string")
	viper.SetDefault("hosted_domain", "*")
	viper.ReadInConfig()
	viper.AutomaticEnv()

	err := viper.Unmarshal(&cfg)

	if err != nil {
		log.Fatalln(err)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)

	if err != nil {
		log.Fatalln(err)
	}

	parsedURL, err := url.Parse(cfg.URL)

	if err != nil {
		log.Fatalln(err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "/callback")

	oa = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		RedirectURL:  parsedURL.String(),
		Endpoint:     provider.Endpoint(),
	}

	vrf = provider.Verifier(&oidc.Config{
		ClientID: oa.ClientID,
	})
}

func main() {
	e := utils.NewEcho("server")
	e.Debug = cfg.Debug

	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(cfg.SessionKey))))

	e.GET("/", start())
	e.GET("/callback", callback())
	e.GET("/session/new", newSession())
	e.POST("/session", createSession())

	e.Logger.Fatal(e.Start(cfg.Addr()))
}

func start() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		state := utils.SecureRandString(32)
		rawRedirectURI := c.QueryParam("redirect_uri")
		sess.Values["state"] = state

		if rawRedirectURI != "" {
			redirectURI, err := url.Parse(rawRedirectURI)

			if err != nil {
				return err
			}

			ipAddr := net.ParseIP(redirectURI.Hostname())

			if !ipAddr.IsLoopback() {
				return echo.NewHTTPError(http.StatusBadRequest, "redirect_url: only loopback ip address are allowed as host")
			}
		}

		sess.Values["redirectURI"] = rawRedirectURI
		sess.Save(c.Request(), c.Response())

		redirectURI := oa.AuthCodeURL(
			state,
			oauth2.AccessTypeOnline,
			oauth2.SetAuthURLParam("prompt", "select_account"),
			oauth2.SetAuthURLParam("hd", cfg.HostedDomain),
		)

		return c.Redirect(http.StatusFound, redirectURI)
	}
}

func callback() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		paramState := c.QueryParam("state")
		sessState := sess.Values["state"]

		if paramState != sessState {
			return echo.NewHTTPError(http.StatusTeapot, "I'm a teapot")
		}

		redirectURI, err := url.Parse("/session/new")

		if err != nil {
			return err
		}

		redirectURI.RawQuery = c.QueryParams().Encode()

		return c.Redirect(302, redirectURI.String())
	}
}

func newSession() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		paramCode := c.QueryParam("code")

		token, err := oa.Exchange(
			oauth2.NoContext,
			paramCode,
		)

		if err != nil {
			return err
		}

		rawIDToken := token.Extra("id_token").(string)
		idToken, err := vrf.Verify(ctx, rawIDToken)

		if err != nil {
			return err
		}

		claims := new(Claims)
		err = idToken.Claims(&claims)

		if err != nil {
			return err
		}

		srv, err := admin.New(oa.Client(ctx, token))

		if err != nil {
			return err
		}

		resp, err := srv.Users.
			Get(claims.Email).
			CustomFieldMask("AmazonWebService").
			Projection("custom").
			Fields("customSchemas").
			Do()

		if err != nil {
			return err
		}

		schema := new(Schema)
		err = json.Unmarshal(resp.CustomSchemas["AmazonWebService"], &schema)

		if err != nil {
			return err
		}

		rolesByAccount := make(RolesByAccount)

		for _, v := range schema.Roles {
			rawArn := strings.Split(v.Value, ",")[0]
			res, err := arn.Parse(rawArn)

			if err != nil {
				return err
			}

			rolesByAccount[res.AccountID] = append(rolesByAccount[res.AccountID], res)
		}

		if err != nil {
			return err
		}

		state := new(State)
		state.RolesByAccount = rolesByAccount
		state.IDToken = rawIDToken
		state.Email = claims.Email
		state.Duration = int64(idToken.Expiry.Sub(time.Now()).Seconds())
		state.CSRFToken = utils.SecureRandString(32)

		b, err := json.Marshal(state)

		if err != nil {
			return err
		}

		data := new(NewSessionData)
		data.RolesByAccount = rolesByAccount
		data.StateData = base64.StdEncoding.EncodeToString(b)

		sess.Values["state"] = data.StateData
		sess.Save(c.Request(), c.Response())

		return c.Render(200, "new_session.html", data)
	}
}

func createSession() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		params, err := c.FormParams()

		if err != nil {
			return err
		}

		paramState := params.Get("state")
		sessState := sess.Values["state"]

		if paramState != sessState {
			return echo.NewHTTPError(http.StatusTeapot, "I'm a teapot")
		}

		b, err := base64.StdEncoding.DecodeString(paramState)

		if err != nil {
			return err
		}

		state := new(State)
		err = json.Unmarshal(b, state)

		if err != nil {
			return err
		}

		role := params.Get("role")

		if !state.RolesByAccount.Has(role) {
			return echo.NewHTTPError(http.StatusTeapot, "You're not allowed to assume the selected role")
		}

		stsSrv := sts.New(aws_session.Must(aws_session.NewSession()))

		stsResp, err := stsSrv.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(params.Get("role")),
			RoleSessionName:  aws.String(state.Email),
			DurationSeconds:  aws.Int64(state.Duration),
			WebIdentityToken: aws.String(state.IDToken),
		})

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, err)
		}

		rawRedirectURI := sess.Values["redirectURI"]

		if rawRedirectURI != "" {
			// redirect to client
			redirectURI, err := url.Parse(rawRedirectURI.(string))

			if err != nil {
				return err
			}

			q := redirectURI.Query()

			rawCreds := fmt.Sprintf("%v:%v:%v",
				*stsResp.Credentials.AccessKeyId,
				*stsResp.Credentials.SecretAccessKey,
				*stsResp.Credentials.SessionToken,
			)

			base64Creds := base64.URLEncoding.EncodeToString([]byte(rawCreds))

			q.Set("cloudcreds", base64Creds)

			redirectURI.RawQuery = q.Encode()

			return c.Redirect(http.StatusFound, redirectURI.String())
		} else {
			// redirect to console
			creds, err := json.Marshal(map[string]string{
				"sessionId":    *stsResp.Credentials.AccessKeyId,
				"sessionKey":   *stsResp.Credentials.SecretAccessKey,
				"sessionToken": *stsResp.Credentials.SessionToken,
			})

			if err != nil {
				return err
			}

			redirectURI, err := url.Parse("https://signin.aws.amazon.com/federation")

			if err != nil {
				return err
			}

			q := redirectURI.Query()
			q.Set("Action", "getSigninToken")
			q.Set("SessionDuration", "3600")
			q.Set("Session", string(creds))

			redirectURI.RawQuery = q.Encode()

			fedRespRaw, err := http.Get(redirectURI.String())

			if err != nil {
				return err
			}

			fedRespBody, err := ioutil.ReadAll(fedRespRaw.Body)

			if err != nil {
				return err
			}

			var fedResp struct {
				SigninToken string `json:"SigninToken"`
			}

			err = json.Unmarshal(fedRespBody, &fedResp)

			if err != nil {
				return err
			}

			if err != nil {
				return err
			}

			redirectURI.RawQuery = ""

			q = redirectURI.Query()
			q.Set("Action", "login")
			q.Set("Issuer", cfg.URL)
			q.Set("Destination", "https://console.aws.amazon.com")
			q.Set("SigninToken", fedResp.SigninToken)

			redirectURI.RawQuery = q.Encode()

			return c.Redirect(302, redirectURI.String())
		}
	}
}

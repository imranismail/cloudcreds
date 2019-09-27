package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/imranismail/cloudcreds/server/session"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"

	admin "google.golang.org/api/admin/directory/v1"
)

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

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

type Config struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Port         string   `mapstructure:"port"`
	Host         string   `mapstructure:"host"`
	HostedDomain string   `mapstructure:"hosted_domain"`
	Scopes       []string `mapstructure:"scopes"`
	IssuerURL    string   `mapstructure:"issuer_url"`
	Debug        bool     `mapstructure:"debug"`
	SessionKey   string   `mapstructure:"session_key"`
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%v:%v", c.Host, c.Port)
}

func (c *Config) URL() string {
	return fmt.Sprintf("http://%v:%v", c.Host, c.Port)
}

var cfg *Config
var vrf *oidc.IDTokenVerifier
var oa *oauth2.Config
var ctx context.Context

func init() {
	gob.Register([]arn.ARN{})

	ctx = context.TODO()

	replacer := strings.NewReplacer(".", "_")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetDefault("port", "1337")
	viper.SetDefault("host", "127.0.0.1")
	viper.SetDefault("debug", false)
	viper.SetDefault("session_key", "please-set-this-to-a-high-entropy-string")
	viper.SetDefault("hosted_domain", "*")
	viper.ReadInConfig()
	viper.AutomaticEnv()
	err := viper.Unmarshal(&cfg)

	if err != nil {
		log.Fatal(err)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)

	if err != nil {
		log.Fatal(err)
	}

	oa = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		RedirectURL:  "http://127.0.0.1:1337/callback",
		Endpoint:     provider.Endpoint(),
	}

	vrf = provider.Verifier(&oidc.Config{
		ClientID: oa.ClientID,
	})
}

func main() {
	e := echo.New()
	e.Debug = cfg.Debug
	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.ParseGlob("server/templates/*.html")),
	}

	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(cfg.SessionKey))))
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:csrf",
	}))

	e.GET("/", home())
	e.GET("/callback", callback())
	e.GET("/session/new", newSession())
	e.POST("/session", createSession())

	e.Logger.Fatal(e.Start(cfg.Addr()))
}

func genRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func secureRandString(s int) (string, error) {
	b, err := genRandBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func home() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		state, err := secureRandString(32)

		if err != nil {
			return err
		}

		sess.Values["state"] = state
		sess.Save(c.Request(), c.Response())

		redirectURL := oa.AuthCodeURL(
			state,
			oauth2.AccessTypeOnline,
			oauth2.SetAuthURLParam("prompt", "select_account"),
			oauth2.SetAuthURLParam("hd", cfg.HostedDomain),
		)

		return c.Redirect(http.StatusFound, redirectURL)
	}
}

func callback() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("default", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
		}

		remoteState := c.QueryParam("state")
		localState := sess.Values["state"]

		if localState != remoteState {
			return echo.NewHTTPError(http.StatusTeapot, "CSRF prevented because of invalid state")
		}

		redirectURL, err := url.Parse("/session/new")

		if err != nil {
			return err
		}

		redirectURL.RawQuery = c.QueryParams().Encode()

		return c.Redirect(302, redirectURL.String())
	}
}

func newSession() func(echo.Context) error {
	return func(c echo.Context) error {
		paramCode := c.QueryParam("code")

		token, err := oa.Exchange(
			oauth2.NoContext,
			paramCode,
		)

		if err != nil {
			return err
		}

		rawIdToken := token.Extra("id_token").(string)
		idToken, err := vrf.Verify(ctx, rawIdToken)

		if err != nil {
			return err
		}

		var claims Claims
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

		var schema Schema

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

		var data struct {
			RolesByAccount RolesByAccount
			Email          string
			IDToken        string
			CSRFToken      string
		}

		data.RolesByAccount = rolesByAccount
		data.Email = claims.Email
		data.IDToken = rawIdToken
		data.CSRFToken = c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)

		return c.Render(200, "new_session.html", data)
	}
}

func createSession() func(echo.Context) error {
	return func(c echo.Context) error {
		params, _ := c.FormParams()

		stsSrv := sts.New(aws_session.Must(aws_session.NewSession()))

		stsResp, err := stsSrv.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(params.Get("role")),
			RoleSessionName:  aws.String(params.Get("email")),
			DurationSeconds:  aws.Int64(3600),
			WebIdentityToken: aws.String(params.Get("idToken")),
		})

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, err)
		}

		creds, err := json.Marshal(map[string]string{
			"sessionId":    *stsResp.Credentials.AccessKeyId,
			"sessionKey":   *stsResp.Credentials.SecretAccessKey,
			"sessionToken": *stsResp.Credentials.SessionToken,
		})

		if err != nil {
			return err
		}

		fedURL, err := url.Parse("https://signin.aws.amazon.com/federation")

		if err != nil {
			return err
		}

		fedQs := make(url.Values)
		fedQs.Set("Action", "getSigninToken")
		fedQs.Set("SessionDuration", "3600")
		fedQs.Set("Session", string(creds))

		fedURL.RawQuery = fedQs.Encode()

		fedRespRaw, err := http.Get(fedURL.String())

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

		redirectQs := make(url.Values)
		redirectQs.Set("Action", "login")
		redirectQs.Set("Issuer", cfg.Host)
		redirectQs.Set("Destination", "https://console.aws.amazon.com")
		redirectQs.Set("SigninToken", fedResp.SigninToken)

		fedURL.RawQuery = redirectQs.Encode()

		return c.Redirect(302, fedURL.String())
		// fmt.Printf("AWS_ACCESS_KEY_ID=%v\n", *stsResp.Credentials.AccessKeyId)
		// fmt.Printf("AWS_SECRET_ACCESS_KEY=%v\n", *stsResp.Credentials.SecretAccessKey)
		// fmt.Printf("AWS_SESSION_TOKEN=%v\n", *stsResp.Credentials.SessionToken)

		// cancelCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		// defer c.Echo().Shutdown(cancelCtx)
		// defer cancel()

		// return c.Render(http.StatusOK, "message.html", map[string]interface{}{
		// 	"message": "Role assumed, please close this window and check your terminal output",
		// 	"context": "success",
		// 	"color":   "green",
		// })

		// sess, _ := session.Get("_cloudcreds", c)
		// sess.Options = &sessions.Options{
		// 	Path:     "/",
		// 	MaxAge:   0,
		// 	HttpOnly: true,
		// }

		// schema := sess.Values["roles"]
		// email := sess.Values["email"]
		// idToken := sess.Values["idToken"]

		// fmt.Println(schema)
		// fmt.Println(email)
		// fmt.Println(idToken)

		// return c.Render(200, "roles.html", map[string]interface{}{
		// 	"schema": schema,
		// })
	}
}

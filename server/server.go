package server

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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/imranismail/cloudcreds/templates"
	"github.com/imranismail/cloudcreds/utils"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	admin "google.golang.org/api/admin/directory/v1"
	option "google.golang.org/api/option"
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

type State struct {
	RolesByAccount templates.RolesByAccount
	IDToken        string
	CSRFToken      string
	Email          string
	Duration       int64
}

type FedResp struct {
	SigninToken string
}

func serverAddr() string {
	return fmt.Sprintf("%s:%d", viper.GetString("server.hostname"), viper.GetInt("server.port"))
}

var vrf *oidc.IDTokenVerifier
var oa *oauth2.Config
var ctx context.Context
var adminSvc *admin.Service
var stsSvc *sts.STS
var iss = "https://accounts.google.com"

func Init() {
	ctx = context.Background()

	stsSvc = sts.New(aws_session.Must(aws_session.NewSession()))

	parsedURL, err := url.Parse(viper.GetString("server.url"))

	if err != nil {
		log.Fatalln(err)
	}

	parsedURL.Path = path.Join(parsedURL.Path, "/callback")

	oa, err = google.ConfigFromJSON(
		[]byte(viper.GetString("server.client_credentials")),
		"openid",
		"email",
		"profile",
	)

	if err != nil {
		log.Fatalln(err)
	}

	cfg, err := google.JWTConfigFromJSON(
		[]byte(viper.GetString("server.service_account_key")),
		admin.AdminDirectoryUserReadonlyScope,
	)

	if err != nil {
		log.Fatalln(err)
	}

	cfg.Subject = viper.GetString("server.admin_email")

	ts := cfg.TokenSource(ctx)

	adminSvc, err = admin.NewService(
		ctx,
		option.WithTokenSource(ts),
	)

	if err != nil {
		log.Fatalln(err)
	}

	provider, err := oidc.NewProvider(ctx, iss)

	if err != nil {
		log.Fatalln(err)
	}

	vrf = provider.Verifier(&oidc.Config{
		ClientID: oa.ClientID,
	})
}

func Serve() {
	srv := utils.NewEcho()
	srv.Debug = viper.GetBool("debug")

	srv.Use(middleware.Logger())
	srv.Use(session.Middleware(sessions.NewCookieStore([]byte(viper.GetString("server.session_key")))))

	srv.GET("/", handleStart())
	srv.GET("/callback", handleCallback())
	srv.GET("/session/new", handleNewSession())
	srv.POST("/session", handleCreateSession())

	srv.Logger.Fatal(srv.Start(serverAddr()))
}

func handleStart() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("_cloudcreds", c)
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
			oauth2.SetAuthURLParam("hd", viper.GetString("server.hosted_domain")),
		)

		return c.Redirect(http.StatusFound, redirectURI)
	}
}

func handleCallback() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("_cloudcreds", c)
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

func handleNewSession() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("_cloudcreds", c)
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

		state := new(State)
		state.IDToken = rawIDToken
		state.Email = claims.Email
		state.Duration = int64(idToken.Expiry.Sub(time.Now()).Seconds())
		state.CSRFToken = utils.SecureRandString(32)

		stateBytes, err := json.Marshal(state)

		if err != nil {
			return err
		}

		stateData := base64.StdEncoding.EncodeToString(stateBytes)

		sess.Values["state"] = stateData
		sess.Save(c.Request(), c.Response())

		rolesByAccount, err := getRolesByAccount(claims.Email)

		if err != nil {
			return err
		}

		return c.HTML(http.StatusOK, templates.NewSession(&rolesByAccount, stateData))
	}
}

func handleCreateSession() func(echo.Context) error {
	return func(c echo.Context) error {
		sess, _ := session.Get("_cloudcreds", c)
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

		rolesByAccount, err := getRolesByAccount(state.Email)

		if err != nil {
			return err
		}

		if !rolesByAccount.Has(role) {
			return echo.NewHTTPError(http.StatusTeapot, "You're not allowed to assume the selected role")
		}

		stsResp, err := stsSvc.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
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
			creds, err := json.Marshal(map[string]string{
				"sessionId":    *stsResp.Credentials.AccessKeyId,
				"sessionKey":   *stsResp.Credentials.SecretAccessKey,
				"sessionToken": *stsResp.Credentials.SessionToken,
			})

			if err != nil {
				return err
			}

			fedURI, err := url.Parse("https://signin.aws.amazon.com/federation")

			if err != nil {
				return err
			}

			q := fedURI.Query()
			q.Set("Action", "getSigninToken")
			q.Set("SessionDuration", strconv.FormatInt(state.Duration, 10))
			q.Set("Session", string(creds))

			fedURI.RawQuery = q.Encode()

			fedRespRaw, err := http.Get(fedURI.String())

			if err != nil {
				return err
			}

			fedRespBody, err := ioutil.ReadAll(fedRespRaw.Body)

			if err != nil {
				return err
			}

			fedResp := new(FedResp)
			err = json.Unmarshal(fedRespBody, &fedResp)

			if err != nil {
				return err
			}

			if err != nil {
				return err
			}

			fedURI.RawQuery = ""

			q = fedURI.Query()
			q.Set("Action", "login")
			q.Set("Issuer", viper.GetString("server.url"))
			q.Set("Destination", "https://console.aws.amazon.com/")
			q.Set("SigninToken", fedResp.SigninToken)

			fedURI.RawQuery = q.Encode()

			return c.Redirect(302, fedURI.String())
		}
	}
}

func getRolesByAccount(email string) (templates.RolesByAccount, error) {
	resp, err := adminSvc.Users.
		Get(email).
		CustomFieldMask("AmazonWebService").
		Projection("custom").
		Fields("customSchemas").
		Do()

	if err != nil {
		return nil, err
	}

	schema := new(Schema)
	err = json.Unmarshal(resp.CustomSchemas["AmazonWebService"], &schema)

	if err != nil {
		return nil, err
	}

	rolesByAccount := make(templates.RolesByAccount)

	for _, v := range schema.Roles {
		rawArn := strings.Split(v.Value, ",")[0]
		res, err := arn.Parse(rawArn)

		if err != nil {
			return nil, err
		}

		rolesByAccount[res.AccountID] = append(rolesByAccount[res.AccountID], res)
	}

	return rolesByAccount, nil
}

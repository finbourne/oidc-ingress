package handlers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	secureCookie "github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type (
	// OidcClient is the configuration data for a client
	OidcClient struct {
		Name             string
		Provider         *oidc.Provider
		ClientID         string
		ClientSecret     string
		NoRedirect       bool
		AllowedRedirects []string
		Scopes           []string
		CookieDomain     string
		CookieSecret     string
		logger           *logrus.Logger
	}
	// Oidc is the configuration data
	Oidc struct {
		clients     map[string]*OidcClient
		stateStorer StateStorer
		logger      *logrus.Logger
	}
)

// StateStorer is the contract used for storing state information temporarily
type StateStorer interface {
	SaveRedirectURIForClient(string, string) (string, error)
	GetRedirectURI(string) (string, string, error)
}

const clientSideRedirectPage = `
<html xmlns="http://www.w3.org/1999/xhtml">    
<head>      
<title>Redirecting</title>      
<meta http-equiv="refresh" content="0;URL='%v'" />    
</head>    
<body> 
<p>Redirecting...</p> 
</body>  
</html>`

// NewOidcHandler creates a new object for handling all oidc authorisation requests.
// externalURL support has been removed. Dynamic host/scheme detection is now used.
func NewOidcHandler(config string, stateStorer StateStorer, logger *logrus.Logger) (*Oidc, error) {

	var clientConfigs []struct {
		Profile          string   `yaml:"profile"`
		Provider         string   `yaml:"provider"`
		ClientID         string   `yaml:"clientID"`
		ClientSecret     string   `yaml:"clientSecret"`
		NoRedirect       bool     `yaml:"noRedirect"`
		AllowedRedirects []string `yaml:"allowedRedirects"`
		Scopes           []string `yaml:"scopes"`
		CookieDomain     string   `yaml:"cookieDomain"`
		CookieSecret     string   `yaml:"cookieSecret"`
	}
	err := yaml.Unmarshal([]byte(config), &clientConfigs)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse OIDC client config")
	}

	// Initialize each unique provider
	providers := make(map[string]*oidc.Provider)
	clients := make(map[string]*OidcClient)

	for _, c := range clientConfigs {
		if len(c.Scopes) == 0 {
			c.Scopes = []string{oidc.ScopeOpenID}
		}
		_, ok := providers[c.Provider]
		if !ok {
			logger.Info("Initialising OIDC discovery endpoint", c.Provider)
			providers[c.Provider], err = oidc.NewProvider(context.Background(), c.Provider)
			if err != nil {
				logger.Error("Unable to initialise provider", err)
				return nil, errors.Wrap(err, "Unable to initialise provider")
			}
		}
		clients[c.Profile] = &OidcClient{
			Name:             c.Profile,
			Provider:         providers[c.Provider],
			ClientID:         c.ClientID,
			ClientSecret:     c.ClientSecret,
			NoRedirect:       c.NoRedirect,
			AllowedRedirects: c.AllowedRedirects,
			Scopes:           c.Scopes,
			CookieDomain:     c.CookieDomain,
			CookieSecret:     c.CookieSecret,
			logger:           logger,
		}
		logger.WithFields(logrus.Fields{
			"method":   "NewOidcHandler",
			"profile":  c.Profile,
			"clientID": c.ClientID,
			"provider": c.Provider,
		}).Debug("Adding configuration.")
	}

	if len(clients) == 0 {
		return nil, errors.New("No OIDC clients configured")
	}
	return &Oidc{clients, stateStorer, logger}, nil
}

// helpers
var verify = func(token string, c OidcClient) error {
	idTokenVerifier := c.Provider.Verifier(
		&oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{"RS256"}},
	)
	_, err := idTokenVerifier.Verify(context.Background(), token)
	return err
}

func (c OidcClient) verifyToken(token string) error {
	return verify(token, c)
}

func (c OidcClient) redirectURL(r *http.Request) string {
	c.logger.WithFields(logrus.Fields{
		"method":         "redirectURL",
		"original-url":   r.Header.Get("X-Original-Url"),
		"redirect-param": r.URL.Query().Get("rd"),
	}).Debug("RedirectURL")

	for name, headers := range r.Header {
		for _, header := range headers {
			c.logger.WithFields(logrus.Fields{
				"method": "redirectURL",
				"header": name,
				"value":  header,
			}).Debug("HEADER")
		}
	}

	var rd string
	if !c.NoRedirect {
		rd = r.URL.Query().Get("rd")
	}

	return rd
}

func (c OidcClient) oAuth2Config(redirect string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     getEndpoint(c),
		RedirectURL:  redirect,
		Scopes:       c.Scopes,
	}
}

var getEndpoint = func(c OidcClient) oauth2.Endpoint {
	return c.Provider.Endpoint()
}

// baseURL derives the external base URL (scheme + host) from the incoming request.
// Order of precedence:
// 1. X-Forwarded-Proto / X-Forwarded-Host (first values)
// 2. r.URL.Scheme (set if the request URL had a scheme when created)
// 3. TLS presence (https if r.TLS != nil)
// 4. Fallback http
func (o Oidc) baseURL(r *http.Request) string {
	// Scheme
	scheme := ""
	if h := r.Header.Get("X-Forwarded-Proto"); h != "" {
		scheme = strings.TrimSpace(strings.Split(h, ",")[0])
	} else if r.URL != nil && r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	} else if r.TLS != nil {
		scheme = "https"
	} else {
		scheme = "http"
	}
	// Host
	host := r.Header.Get("X-Forwarded-Host")
	if host != "" {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	} else {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// deriveCookieDomain returns the domain to use for the auth cookie.
// Rules:
//  1. If a CookieDomain is configured, use it as-is (allows explicit control / advanced cases).
//  2. Otherwise derive from the request host (preferring X-Forwarded-Host if present).
//     a. Strip any port.
//     b. If the host has 3+ labels (e.g. app.env.example.com) drop the left-most label so the
//     cookie is valid for sibling subdomains (env.example.com). This keeps behaviour simple
//     without needing a public suffix list. If only 1-2 labels, keep them unchanged.
//
// This avoids perpetual redirects when a cookie set on one subdomain is not sent to another.
func deriveCookieDomain(configDomain string, r *http.Request) string {
	if configDomain != "" { // Explicitly configured (could already be a parent domain)
		return configDomain
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	} else {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}
	// Strip port if present
	host = strings.Split(host, ":")[0]
	parts := strings.Split(host, ".")
	if len(parts) >= 3 { // drop first label to broaden scope (foo.bar.example.com -> bar.example.com)
		return strings.Join(parts[1:], ".")
	}
	return host
}

// Handlers

var getProfile = func(r *http.Request, paramName string) string {
	return chi.URLParam(r, "profile")
}

// VerifyHandler takes care of verifying if the user is authenticated.VerifyHandler
// Id does this by querying a cookie named after the specific config profile name.
func (o Oidc) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	profile := getProfile(r, "profile")
	o.logger.WithFields(logrus.Fields{
		"method":  "VerifyHandler",
		"profile": profile,
	}).Debug("Verifying for profile.")

	if config, ok := o.clients[profile]; ok {
		hashKey := []byte(config.CookieSecret)
		s := secureCookie.New(hashKey, nil)

		cookie, err := r.Cookie(config.Name)
		if err != nil {
			o.logger.WithFields(logrus.Fields{
				"method": "VerifyHandler",
				"error":  err.Error(),
			}).Warn("Something wrong with the cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var token string
		err = s.Decode(config.Name, cookie.Value, &token)
		o.logger.WithFields(logrus.Fields{
			"method": "VerifyHandler",
			"token":  token,
			"error":  err,
		}).Debug("Decode cookie")
		if token != "" {
			err = config.verifyToken(token)
			if err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	o.logger.WithFields(logrus.Fields{
		"method":  "VerifyHandler",
		"profile": profile,
	}).Warn("Unable to find profile in configuration")
	w.WriteHeader(http.StatusForbidden)
}

// SigninHandler signs a user in via the oauth provider set in the signin request
func (o Oidc) SigninHandler(w http.ResponseWriter, r *http.Request) {
	profile := getProfile(r, "profile")
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
	}).Debug("Signing in")

	config, ok := o.clients[profile]
	if !ok {
		// There's been a configuration error.
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
		}).Warn("Unable to find profile in configuration")

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Configuration error")
		return
	}

	// The request was ok, figure out if we are already signed in, and if not, redirect to our oauth provider.
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
		"config":  config,
	}).Debug("Found config for profile.")

	redirectTo := config.redirectURL(r)
	allowed := false
	for i := range config.AllowedRedirects {
		re := regexp.MustCompile(config.AllowedRedirects[i])
		allowed = allowed || re.MatchString(redirectTo)
		o.logger.WithFields(logrus.Fields{
			"method":             "SigninHandler",
			"profile":            profile,
			"requested-redirect": redirectTo,
			"allowed-redirect":   config.AllowedRedirects[i],
			"is-allowed":         allowed,
		}).Debug("Can redirect?")
	}

	if !allowed {
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
		}).Error("Invalid redirect request")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Unacceptable redirect")
		return
	}

	cookie, err := r.Cookie(config.Name)
	o.logger.WithFields(logrus.Fields{
		"method":  "SigninHandler",
		"profile": profile,
		"cookie":  cookie,
		"error":   err,
	}).Debug("Finding Cookie")

	if err == nil && cookie != nil {
		hashKey := []byte(config.CookieSecret)
		s := secureCookie.New(hashKey, nil)

		var token string
		err = s.Decode(config.Name, cookie.Value, &token)
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
			"cookie":  cookie,
			"token":   token,
			"error":   err,
		}).Debug("Decoded cookie value")

		if token != "" {
			err = config.verifyToken(token)
			if err == nil {
				if r.URL.Query().Get("rd") != "" {
					http.Redirect(w, r, r.URL.Query().Get("rd"), http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	state, err := o.stateStorer.SaveRedirectURIForClient(profile, redirectTo)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "SigninHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Unable to save auth request data and generate state token.")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Unable to save auth request data and generate state token.")
		return
	}

	o.logger.WithFields(logrus.Fields{
		"method":         "SigninHandler",
		"profile":        profile,
		"redirectBackTo": redirectTo,
		"stateToken":     state,
	}).Info("Authentication required - redirecting.")

	callbackURL := fmt.Sprintf("%s/auth/callback", o.baseURL(r))
	http.Redirect(w, r, config.oAuth2Config(callbackURL).AuthCodeURL(state), http.StatusFound)
}

var getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) {
	return config.oAuth2Config(fmt.Sprintf("%v/auth/callback", url)).Exchange(context.Background(), r.URL.Query().Get("code"))
}

var getIDToken = func(oauth2 *oauth2.Token) string {
	return oauth2.Extra("id_token").(string)
}

// CallbackHandler handles the return call from the oauth provider after authentication
func (o Oidc) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	profile, redirectURL, err := o.stateStorer.GetRedirectURI(state)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Error rehydrating state")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid state")
		return
	}

	o.logger.WithFields(logrus.Fields{
		"method":      "CallbackHandler",
		"profile":     profile,
		"state":       state,
		"redirectURL": redirectURL,
	}).Info("Callback received from oauth provider.")

	config, ok := o.clients[profile]
	if !ok {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
		}).Error("Profile not found in config.")

		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, http.StatusText(http.StatusForbidden))
		return
	}

	oauth2Token, err := getOAuth2Token(o.baseURL(r), r, config)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Failed to exchange token.")

		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Failed to exchange token: %s", err.Error())
		return
	}

	rawIDToken := getIDToken(oauth2Token)
	err = config.verifyToken(rawIDToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed to verify ID Token: %s", err.Error())
		return
	}

	hashKey := []byte(config.CookieSecret)
	s := secureCookie.New(hashKey, nil)
	encoded, err := s.Encode(config.Name, rawIDToken)
	if err != nil {
		o.logger.WithFields(logrus.Fields{
			"method":  "CallbackHandler",
			"profile": profile,
			"error":   err.Error(),
		}).Error("Error encoding cookie value.")
	}

	cookie := http.Cookie{
		Name:     config.Name,
		Path:     "/",
		Domain:   deriveCookieDomain(config.CookieDomain, r),
		Value:    encoded,
		SameSite: 2,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	o.logger.WithFields(logrus.Fields{
		"method":  "CallbackHandler",
		"profile": profile,
		"cookie":  cookie,
	}).Debug("Cookie set - redirecting back to application.")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("rd") != "" {
		fmt.Fprintf(w, clientSideRedirectPage, r.URL.Query().Get("rd"))
		return
	}
	fmt.Fprintf(w, clientSideRedirectPage, redirectURL)
}

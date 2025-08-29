package handlers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	oidc "github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	secureCookie "github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func getOidc(returnParam string, sa string) *Oidc {
	getProfile = func(r *http.Request, paramName string) string {
		return returnParam
	}
	getEndpoint = func(c OidcClient) oauth2.Endpoint {
		return oauth2.Endpoint{}
	}

	logger := logrus.New()
	// logger.Level = logrus.DebugLevel

	stateStorer := NewRedisStateStorer(sa, logger)
	providers := make(map[string]*oidc.Provider)
	clients := make(map[string]*OidcClient)
	providers["test"] = &oidc.Provider{}
	clients["test"] = &OidcClient{
		Name:             "test",
		Provider:         providers["test"],
		ClientID:         "finbourne.com",
		ClientSecret:     "big_secret",
		NoRedirect:       false,
		AllowedRedirects: []string{"https://.*.hoo.com"},
		Scopes:           []string{"openid", "email", "groups"},
		CookieDomain:     "boo.hoo.com",
		CookieSecret:     "big_super_secret_key",
		logger:           logger,
	}
	return &Oidc{clients, stateStorer, logger}
}
func TestVerifyExpiredTokenReturns401(t *testing.T) {

	oidc := getOidc("test", "")

	req, _ := http.NewRequest("GET", "http://boo.hoo.com/auth/verify/test", nil)
	req.AddCookie(&http.Cookie{Name: "test", Value: "TU3MzgzMDY1N3xfZ05fREFELUEzcGxlVXB5WVZkUmFVOXBTa1JrYlhBMVdXNXJkMWxVVmt0V1JGbzBUbXRPTTFkWGJESlpNalV6WVZWNFptSkVUbEpPYWtwdVpVVTFZV0o2UVRGTk1Fb3hWVlJPV2tscGQybFpWM2h1U1dwdmFWVnNUWGxPVkZscFpsRXVaWGxLZW1SWFNXbFBhVWwzVFVoVmVHRlhlRFJaVjFaNFRsVTVOVk5zU1hsTlJFWXdUbmxKYzBsdFZuUlpWMnh6U1dwdmFXTkhSakZpUXpWNldWaFdkVnBIVm5sak1FSnRZVmMxYVdJelZubGliVlYxV1RJNWRFbHBkMmxrYlZaNVNXcHZlRXhEU25Cak0wMXBUMmxLYjJSSVVuZGplbTkyVERKYWNHSnRTblprV0VwMVdsTTFkbUV6VW1oTWJVNTJZbE5KYzBsdFJqRmFRMGsyU1dwQ2RsbFVUbk5qYmxsM1RucEdjMW95WkhGa1JHdzBUVmhSTTBscGQybGhWMFl3U1dwdmVFNVVZM3BPUkd0NVQwUnJkMHhEU214bFNFRnBUMnBGTVU1NlRUQlBWRmt3VDFSQmMwbHRjREJoVTBrMlNXdHNSVXhzWkVWVFZrcFVaRlJHTkdGRVJuVlRNRTB4WlcxbmVsUXlXbGRhVkZwWFlXczFiazlIT1VoWFZrSkRVbnBTWVZGcmJ6TlZha3A0VWpCVmFVeERTbWhpV0VscFQyeHphV0ZJWkhKSmFYZHBZMGhrYTBscGQybGlWMXBvU1d3d2MwbHRiR3RqUTBrMlNXcEJkMko2Um5CaGFtUnBZMGRXVFdJeVNreFVSVmswVFZoUk0wbHBkMmxaV0ZZd1lVWTVNR0ZYTVd4SmFtOTRUbFJqZWs1RVl6Tk5lbU13VEVOS2FHUkdPVzlaV0U1dlNXcHZhVkV5YkUxalJXUkpaVlYwTUZJeVdtOVhSa3BhVlRKU1VGVnRPWE5hZVVvNUxreFpWelJTZUZKWmJFOHRjekpuUXpCaFRtUkRhMmREUVMxSmNXTnVUbE41TVRsTVVWQnljRTVRWldGVVprMUdiRFJZVFVGb2IxaEVZVm8yU0U0NVEzRlFabWRKYzE5VFVrOVdiVkZNU2pWc1FYaE5RbXh3WjBoRFJsWlNaR0Y2ZUU1WVEzUklZWEZSYTJ0MFRqRlZhMDlmTkhWMlptaE5VVFJOTm1kSFNsZDBORVZZVTA1RWVEZzRjVGhGVFZWTGExQk1YMmROZDNCS2IzcFNOVWxwU0VkU1ZVRlhTbWhoYkVSVVF6bHZkakp3VEZVNFRGRjNhMjFHV1VsTk5rSmZabVp4VDNWSFNXdHliekV4TUVWbGVIaERUSGRTYWtsZmRIQTVTVFpCT1c5d05ERjZMWGM0V2podU5XSm9NRk5QVlVsR2NtZEdaVEF6ZG1oU1ZYaDFORmxaTmxCS2NXZFhjelZVTldaakxYRmxhR0pqTFc1elFVTmFTVnByTkVrd2JYUkJYM2RFY1RSNGNHdG1aRWRtUmt4dlRUaHJaV3BDVUU1aUxWRlhVRWg1ZDAxelNIcFhWbmd0WldKelZtcEZVSEZPU21OVFp3PT18v-kgGri2BSjgtKibYXR91fF-xKrVox2BHAs3wUDPjcA="})
	rr := httptest.NewRecorder()
	oidc.VerifyHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 401, resp.StatusCode)
}

func TestVerifyNoCookieReturns401(t *testing.T) {
	oidc := getOidc("test", "")

	req, _ := http.NewRequest("GET", "http://boo.hoo.com/auth/verify/test", nil)
	rr := httptest.NewRecorder()
	oidc.VerifyHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 401, resp.StatusCode)
}

func TestVerifyInvalidProfileReturns403(t *testing.T) {
	oidc := getOidc("blah", "")

	req, _ := http.NewRequest("GET", "http://boo.hoo.com/auth/verify/blah", nil)
	rr := httptest.NewRecorder()
	oidc.VerifyHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 403, resp.StatusCode)
}

func TestSigninConfigError500(t *testing.T) {
	oidc := getOidc("blah", "")

	req, _ := http.NewRequest("GET", "http://boo.hoo.com/auth/signin/test", nil)
	rr := httptest.NewRecorder()
	oidc.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 500, resp.StatusCode)
	assert.Equal(t, "Configuration error", string(body))
}

func TestSigninInvalidRedirct400(t *testing.T) {
	oidc := getOidc("test", "")

	req, _ := http.NewRequest("GET", "http://boo.hoo.com/auth/signin/test?rd=http://invalid.redirect.com", nil)
	rr := httptest.NewRecorder()
	oidc.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "Unacceptable redirect", string(body))
}

func TestSigninWithExpiredCookie302(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()
	oidc := getOidc("test", mr.Addr())

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/signin/test?rd=https://boo.hoo.com", nil)
	req.AddCookie(&http.Cookie{Name: "test", Value: "TU3MzgzMDY1N3xfZ05fREFELUEzcGxlVXB5WVZkUmFVOXBTa1JrYlhBMVdXNXJkMWxVVmt0V1JGbzBUbXRPTTFkWGJESlpNalV6WVZWNFptSkVUbEpPYWtwdVpVVTFZV0o2UVRGTk1Fb3hWVlJPV2tscGQybFpWM2h1U1dwdmFWVnNUWGxPVkZscFpsRXVaWGxLZW1SWFNXbFBhVWwzVFVoVmVHRlhlRFJaVjFaNFRsVTVOVk5zU1hsTlJFWXdUbmxKYzBsdFZuUlpWMnh6U1dwdmFXTkhSakZpUXpWNldWaFdkVnBIVm5sak1FSnRZVmMxYVdJelZubGliVlYxV1RJNWRFbHBkMmxrYlZaNVNXcHZlRXhEU25Cak0wMXBUMmxLYjJSSVVuZGplbTkyVERKYWNHSnRTblprV0VwMVdsTTFkbUV6VW1oTWJVNTJZbE5KYzBsdFJqRmFRMGsyU1dwQ2RsbFVUbk5qYmxsM1RucEdjMW95WkhGa1JHdzBUVmhSTTBscGQybGhWMFl3U1dwdmVFNVVZM3BPUkd0NVQwUnJkMHhEU214bFNFRnBUMnBGTVU1NlRUQlBWRmt3VDFSQmMwbHRjREJoVTBrMlNXdHNSVXhzWkVWVFZrcFVaRlJHTkdGRVJuVlRNRTB4WlcxbmVsUXlXbGRhVkZwWFlXczFiazlIT1VoWFZrSkRVbnBTWVZGcmJ6TlZha3A0VWpCVmFVeERTbWhpV0VscFQyeHphV0ZJWkhKSmFYZHBZMGhrYTBscGQybGlWMXBvU1d3d2MwbHRiR3RqUTBrMlNXcEJkMko2Um5CaGFtUnBZMGRXVFdJeVNreFVSVmswVFZoUk0wbHBkMmxaV0ZZd1lVWTVNR0ZYTVd4SmFtOTRUbFJqZWs1RVl6Tk5lbU13VEVOS2FHUkdPVzlaV0U1dlNXcHZhVkV5YkUxalJXUkpaVlYwTUZJeVdtOVhSa3BhVlRKU1VGVnRPWE5hZVVvNUxreFpWelJTZUZKWmJFOHRjekpuUXpCaFRtUkRhMmREUVMxSmNXTnVUbE41TVRsTVVWQnljRTVRWldGVVprMUdiRFJZVFVGb2IxaEVZVm8yU0U0NVEzRlFabWRKYzE5VFVrOVdiVkZNU2pWc1FYaE5RbXh3WjBoRFJsWlNaR0Y2ZUU1WVEzUklZWEZSYTJ0MFRqRlZhMDlmTkhWMlptaE5VVFJOTm1kSFNsZDBORVZZVTA1RWVEZzRjVGhGVFZWTGExQk1YMmROZDNCS2IzcFNOVWxwU0VkU1ZVRlhTbWhoYkVSVVF6bHZkakp3VEZVNFRGRjNhMjFHV1VsTk5rSmZabVp4VDNWSFNXdHliekV4TUVWbGVIaERUSGRTYWtsZmRIQTVTVFpCT1c5d05ERjZMWGM0V2podU5XSm9NRk5QVlVsR2NtZEdaVEF6ZG1oU1ZYaDFORmxaTmxCS2NXZFhjelZVTldaakxYRmxhR0pqTFc1elFVTmFTVnByTkVrd2JYUkJYM2RFY1RSNGNHdG1aRWRtUmt4dlRUaHJaV3BDVUU1aUxWRlhVRWg1ZDAxelNIcFhWbmd0WldKelZtcEZVSEZPU21OVFp3PT18v-kgGri2BSjgtKibYXR91fF-xKrVox2BHAs3wUDPjcA="})
	rr := httptest.NewRecorder()
	oidc.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)
}

func TestSigninWithDeadStorageProvider(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	mr.Close()

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/signin/test?rd=https://boo.hoo.com", nil)
	rr := httptest.NewRecorder()
	oidc.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "Unable to save auth request data and generate state token.", string(body))
}

func TestSigninWithValidToken(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()
	// oidc := getOidc("test", mr.Addr())
	getProfile = func(r *http.Request, paramName string) string {
		return "test"
	}
	verify = func(token string, c OidcClient) error {
		return nil
	}

	logger := logrus.New()
	// logger.SetLevel(logrus.DebugLevel)

	config := `
- profile: test
  provider: https://finbourne.okta.com
  clientID: finbourne
  clientSecret: big_secret
  noRedirect: false
  allowedRedirects: 
  - https://boo.hoo.com
  scopes:
  - openid
  - email
  - groups
  cookieDomain: boo.hoo.com
  cookieSecret: big_super_secret_key
`
	oidc, _ := NewOidcHandler(config, NewRedisStateStorer(mr.Addr(), logger), logger)

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/signin/test?rd=https://boo.hoo.com", nil)
	req.AddCookie(&http.Cookie{Name: "test", Value: getValidCookieValue()})
	rr := httptest.NewRecorder()
	oidc.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)
	location, _ := resp.Location()
	assert.Equal(t, "https://boo.hoo.com", location.String())
}

func getValidCookieValue() string {
	s := secureCookie.New([]byte("big_super_secret_key"), nil)
	encoded, _ := s.Encode("test", createJwtToken("finbourne"))
	return encoded
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func createJwtToken(audience string) string {

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: "testuser",
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "https://finbourne.okta.com",
			Audience:  audience,
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	secret := []byte("big_secret")
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return ""
	}

	return tokenString
}

// Please leave this as a method to get information for use in tests in future if needed.
// func TestDecodeCookie(t *testing.T) {
// 	cookieValue := "put_cookie_value_here"

// 	s := secureCookie.New([]byte("put_cookie_secret_here"), nil)
// 	var token string
// 	_ = s.Decode("put_profile_name_here", cookieValue, &token)

// 	s = secureCookie.New([]byte("big_super_secret_key"), nil)
// 	encoded, _ := s.Encode("test", token)
// 	println(encoded)
// }

func TestCallbackTookTooLong(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	defer mr.Close()

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/callback?state=nostate", nil)
	rr := httptest.NewRecorder()
	oidc.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "Invalid state", string(body))
}

func TestCallbackNoProfile(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	defer mr.Close()
	mr.Set("/oidc/abcde", "wrongprofile|https://horton.hoo.com")

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/callback?state=abcde", nil)
	rr := httptest.NewRecorder()
	oidc.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 403, resp.StatusCode)
	assert.Equal(t, "Forbidden", string(body))
}

func TestCallbackBadLogin(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	defer mr.Close()
	mr.Set("/oidc/abcde", "test|https://horton.hoo.com")

	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) {
		return nil, errors.New("no token")
	}

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/callback?state=abcde&code=LPear3v7WDBo4ZI8ZeTo", nil)
	rr := httptest.NewRecorder()
	oidc.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, true, strings.HasPrefix(string(body), "Failed to exchange token: no token"))
}

func TestCallbackBadToken(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	defer mr.Close()
	mr.Set("/oidc/abcde", "test|https://horton.hoo.com")

	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) {
		return nil, nil
	}

	getIDToken = func(oauth2 *oauth2.Token) string {
		return createJwtToken("")
	}

	verify = func(token string, c OidcClient) error {
		return errors.New("bad token")
	}

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/callback?state=abcde&code=LPear3v7WDBo4ZI8ZeTo", nil)
	rr := httptest.NewRecorder()
	oidc.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, 500, resp.StatusCode)
	assert.Equal(t, true, strings.HasPrefix(string(body), "Failed to verify ID Token: bad token"))
}

func TestCallbackOKRedirects(t *testing.T) {
	mr, _ := miniredis.Run()
	oidc := getOidc("test", mr.Addr())
	defer mr.Close()
	mr.Set("/oidc/abcde", "test|https://horton.hoo.com")

	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) {
		return nil, nil
	}

	getIDToken = func(oauth2 *oauth2.Token) string {
		return createJwtToken("")
	}

	verify = func(token string, c OidcClient) error {
		return nil
	}

	req, _ := http.NewRequest("GET", "https://boo.hoo.com/auth/callback?state=abcde&code=LPear3v7WDBo4ZI8ZeTo", nil)
	rr := httptest.NewRecorder()
	oidc.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.True(t, strings.Contains(resp.Header["Set-Cookie"][0], "SameSite=Lax"))
	assert.True(t, strings.Contains(resp.Header["Set-Cookie"][0], "Secure"))
	assert.Equal(t, 1, len(resp.Cookies()))
	assert.Equal(t, rr.Body.String(), "\n<html xmlns=\"http://www.w3.org/1999/xhtml\">    \n<head>      \n<title>Redirecting</title>      \n<meta http-equiv=\"refresh\" content=\"0;URL='https://horton.hoo.com'\" />    \n</head>    \n<body> \n<p>Redirecting...</p> \n</body>  \n</html>")

}

// New dynamic base URL tests
func TestSigninDynamicCallbackUsesRequestHost(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	o := getOidc("test", mr.Addr())
	// Ensure predictable auth endpoint so Location is a full URL
	getEndpoint = func(c OidcClient) oauth2.Endpoint {
		return oauth2.Endpoint{AuthURL: "https://authserver/authorize"}
	}
	// rd must match allowed redirect regex
	req, _ := http.NewRequest("GET", "https://foo.hoo.com/auth/signin/test?rd=https://foo.hoo.com", nil)
	rr := httptest.NewRecorder()
	o.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	assert.Equal(t, 302, resp.StatusCode)
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	assert.NoError(t, err)
	redirectURI, _ := url.QueryUnescape(u.Query().Get("redirect_uri"))
	assert.True(t, strings.HasPrefix(redirectURI, "https://foo.hoo.com/auth/callback"), redirectURI)
}

func TestSigninDynamicCallbackUsesForwardedHeaders(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	o := getOidc("test", mr.Addr())
	getEndpoint = func(c OidcClient) oauth2.Endpoint {
		return oauth2.Endpoint{AuthURL: "https://authserver/authorize"}
	}
	req, _ := http.NewRequest("GET", "http://internal/auth/signin/test?rd=https://alice.hoo.com", nil)
	// Simulate proxy headers differing from Host
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "alice.hoo.com")
	rr := httptest.NewRecorder()
	o.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	assert.Equal(t, 302, resp.StatusCode)
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	assert.NoError(t, err)
	redirectURI, _ := url.QueryUnescape(u.Query().Get("redirect_uri"))
	assert.True(t, strings.HasPrefix(redirectURI, "https://alice.hoo.com/auth/callback"), redirectURI)
}

func TestSigninDynamicCallbackFallsBackToHTTP(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	o := getOidc("test", mr.Addr())
	getEndpoint = func(c OidcClient) oauth2.Endpoint {
		return oauth2.Endpoint{AuthURL: "https://authserver/authorize"}
	}
	req, _ := http.NewRequest("GET", "http://bar.hoo.com/auth/signin/test?rd=https://bar.hoo.com", nil)
	rr := httptest.NewRecorder()
	o.SigninHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	assert.Equal(t, 302, resp.StatusCode)
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	assert.NoError(t, err)
	redirectURI, _ := url.QueryUnescape(u.Query().Get("redirect_uri"))
	// Since scheme is http and no forwarded headers/TLS, expect http callback
	assert.True(t, strings.HasPrefix(redirectURI, "http://bar.hoo.com/auth/callback"), redirectURI)
}

// Integration-style tests for cross-subdomain cookie reuse
func TestCrossSubdomainCookieDomainParentWorks(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	logger := logrus.New()
	providers := map[string]*oidc.Provider{"stub": {}}
	clients := map[string]*OidcClient{
		"cookie-setter": {
			Name: "cookie-setter", Provider: providers["stub"], ClientID: "finbourne", ClientSecret: "secret",
			AllowedRedirects: []string{"https://.*.example.com/web-preview/.*"}, Scopes: []string{"openid"}, CookieDomain: "example.com", CookieSecret: "integration_secret_key", logger: logger,
		},
	}
	oidcHandler := &Oidc{clients: clients, stateStorer: NewRedisStateStorer(mr.Addr(), logger), logger: logger}
	// Stub profile extractor to bypass chi routing context
	origGetProfile := getProfile
	getProfile = func(r *http.Request, paramName string) string { return "cookie-setter" }
	defer func() { getProfile = origGetProfile }()

	// Save originals to restore
	origGetOAuth2Token := getOAuth2Token
	origGetIDToken := getIDToken
	origVerify := verify
	defer func() { getOAuth2Token = origGetOAuth2Token; getIDToken = origGetIDToken; verify = origVerify }()

	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) { return nil, nil }
	getIDToken = func(tok *oauth2.Token) string { return "dummy-id-token" }
	verify = func(token string, c OidcClient) error { return nil }

	// 1. Initiate signin to generate state
	signinReq, _ := http.NewRequest("GET", "https://alpha.preview.example.com/auth/signin/cookie-setter?rd=https://alpha.preview.example.com/web-preview/", nil)
	signinRR := httptest.NewRecorder()
	oidcHandler.SigninHandler(signinRR, signinReq)
	assert.Equal(t, 302, signinRR.Code)
	loc := signinRR.Header().Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")
	assert.NotEmpty(t, state)

	// 2. Callback to set cookie on first subdomain
	cbReq, _ := http.NewRequest("GET", fmt.Sprintf("https://alpha.preview.example.com/auth/callback?state=%s&code=abc", state), nil)
	cbRR := httptest.NewRecorder()
	oidcHandler.CallbackHandler(cbRR, cbReq)
	assert.Equal(t, 200, cbRR.Code)
	cookies := cbRR.Result().Cookies()
	if assert.Equal(t, 1, len(cookies)) {
		assert.Equal(t, "cookie-setter", cookies[0].Name)
		assert.Equal(t, "example.com", cookies[0].Domain)
	}

	// 3. Verify on a different sibling subdomain with same cookie
	verifyReq, _ := http.NewRequest("GET", "https://beta.preview.example.com/auth/verify/cookie-setter", nil)
	verifyReq.AddCookie(cookies[0])
	verifyRR := httptest.NewRecorder()
	oidcHandler.VerifyHandler(verifyRR, verifyReq)
	assert.Equal(t, http.StatusNoContent, verifyRR.Code)
}

// Verifies that when a cookie domain is a specific host (not a parent suffix),
// the cookie is not sent to a sibling subdomain and verification fails.
func TestCrossSubdomainHostScopedCookieNotShared(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	logger := logrus.New()
	providers := map[string]*oidc.Provider{"stub": {}}
	clients := map[string]*OidcClient{
		"cookie-setter": {
			Name: "cookie-setter", Provider: providers["stub"], ClientID: "finbourne", ClientSecret: "secret",
			AllowedRedirects: []string{"https://.*.example.com/web-preview/.*"}, Scopes: []string{"openid"}, CookieDomain: "gamma.preview.example.com", CookieSecret: "integration_secret_key", logger: logger,
		},
	}
	oidcHandler := &Oidc{clients: clients, stateStorer: NewRedisStateStorer(mr.Addr(), logger), logger: logger}
	origGetProfile := getProfile
	getProfile = func(r *http.Request, paramName string) string { return "cookie-setter" }
	defer func() { getProfile = origGetProfile }()

	origGetOAuth2Token := getOAuth2Token
	origGetIDToken := getIDToken
	origVerify := verify
	defer func() { getOAuth2Token = origGetOAuth2Token; getIDToken = origGetIDToken; verify = origVerify }()

	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) { return nil, nil }
	getIDToken = func(tok *oauth2.Token) string { return "dummy-id-token" }
	verify = func(token string, c OidcClient) error { return nil }

	signinReq, _ := http.NewRequest("GET", "https://alpha.preview.example.com/auth/signin/cookie-setter?rd=https://alpha.preview.example.com/web-preview/", nil)
	signinRR := httptest.NewRecorder()
	oidcHandler.SigninHandler(signinRR, signinReq)
	assert.Equal(t, 302, signinRR.Code)
	u, _ := url.Parse(signinRR.Header().Get("Location"))
	state := u.Query().Get("state")
	assert.NotEmpty(t, state)

	cbReq, _ := http.NewRequest("GET", fmt.Sprintf("https://alpha.preview.example.com/auth/callback?state=%s&code=abc", state), nil)
	cbRR := httptest.NewRecorder()
	oidcHandler.CallbackHandler(cbRR, cbReq)
	assert.Equal(t, 200, cbRR.Code)
	cookies := cbRR.Result().Cookies()
	if assert.Equal(t, 1, len(cookies)) {
		assert.Equal(t, "alpha.preview.example.com", cookies[0].Domain)
	}

	// Cookie should NOT be sent for sibling not sharing that exact (non-parent) domain
	verifyReq, _ := http.NewRequest("GET", "https://beta.preview.example.com/auth/verify/cookie-setter", nil)
	// simulate browser behavior: cookie domain mismatch => cookie omitted (don't attach)
	verifyRR := httptest.NewRecorder()
	oidcHandler.VerifyHandler(verifyRR, verifyReq)
	assert.Equal(t, http.StatusUnauthorized, verifyRR.Code)
}

// deriveCookieDomain tests
func TestDeriveCookieDomain(t *testing.T) {
	// Helper to build request with optional forwarded host
	newReq := func(host string, fwd string) *http.Request {
		r, _ := http.NewRequest("GET", "https://"+host+"/", nil)
		if fwd != "" {
			r.Header.Set("X-Forwarded-Host", fwd)
		}
		return r
	}
	tests := []struct {
		name         string
		configDomain string
		host         string
		fwdHost      string
		expect       string
	}{
		{"drops first label when >=3 labels", "", "foo.bar.example.com", "", "bar.example.com"},
		{"keeps two-label host", "", "example.com", "", "example.com"},
		{"uses forwarded host", "", "internal:8080", "a.b.c.example.com", "b.c.example.com"},
		{"strips port before processing", "", "foo.bar.example.com:8443", "", "bar.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveCookieDomain(tc.configDomain, newReq(tc.host, tc.fwdHost))
			assert.Equal(t, tc.expect, got)
		})
	}
}

// Ensure CallbackHandler uses derived cookie domain when none configured
func TestCallbackSetsDerivedCookieDomain(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	// Build Oidc instance manually so we can leave CookieDomain empty
	logger := logrus.New()
	providers := map[string]*oidc.Provider{"test": {}}
	clients := map[string]*OidcClient{
		"test": {
			Name:             "test",
			Provider:         providers["test"],
			ClientID:         "finbourne.com",
			ClientSecret:     "big_secret",
			AllowedRedirects: []string{"https://.*.example.com"},
			Scopes:           []string{"openid"},
			CookieDomain:     "", // Force derivation
			CookieSecret:     "big_super_secret_key",
			logger:           logger,
		},
	}
	o := &Oidc{clients: clients, stateStorer: NewRedisStateStorer(mr.Addr(), logger), logger: logger}

	// Prepare state pointing back somewhere valid
	mr.Set("/oidc/abcde", "test|https://app.env.example.com")

	// Stub token exchange & verification
	getOAuth2Token = func(url string, r *http.Request, config *OidcClient) (*oauth2.Token, error) { return nil, nil }
	getIDToken = func(o *oauth2.Token) string { return createJwtToken("") }
	verify = func(token string, c OidcClient) error { return nil }

	req, _ := http.NewRequest("GET", "https://foo.env.example.com/auth/callback?state=abcde&code=XYZ", nil)
	rr := httptest.NewRecorder()
	o.CallbackHandler(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	// Expect cookie domain to drop first label (foo.env.example.com -> env.example.com)
	cookies := resp.Cookies()
	if assert.Equal(t, 1, len(cookies)) {
		assert.Equal(t, "env.example.com", cookies[0].Domain)
	}
}

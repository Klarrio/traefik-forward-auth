package main

import (
	"fmt"
	"time"

	// "reflect"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gitlab.com/Klarrio/traefik-forward-auth/ttlmap"

	"github.com/dgrijalva/jwt-go"
)

/**
 * Utilities
 */

func getJWT(t *testing.T, email string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":   time.Now().Add(time.Duration(time.Second * 10)).Unix(),
		"email": email,
	})
	tokenString, signError := token.SignedString([]byte("a-test-signing-key"))
	if signError != nil {
		t.Fatal("Could not sign the JWT token, reason:", signError)
	}
	return tokenString
}

type TokenValidUserServerHandler struct {
	t *testing.T
}

func (t *TokenValidUserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, fmt.Sprintf(`{"access_token":"%s"}`, getJWT(t.t, "example@example.com")))
}

type UserServerHandler struct{}

func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}

func init() {
	log = CreateLogger("panic", "")
}

func httpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.HeaderMap["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	handler(w, r)

	res := w.Result()
	body, _ := ioutil.ReadAll(res.Body)

	return res, string(body)
}

func newHTTPRequest(uri string) *http.Request {
	r := httptest.NewRequest("", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Uri", uri)
	return r
}

func qsDiff(one, two url.Values) {
	for k := range one {
		if two.Get(k) == "" {
			fmt.Printf("Key missing: %s\n", k)
		}
		if one.Get(k) != two.Get(k) {
			fmt.Printf("Value different for %s: expected: '%s' got: '%s'\n", k, one.Get(k), two.Get(k))
		}
	}
	for k := range two {
		if one.Get(k) == "" {
			fmt.Printf("Extra key: %s\n", k)
		}
	}
}

/**
 * Tests
 */

func TestHandler(t *testing.T) {

	fw = &ForwardAuth{
		Path:         "_oauth",
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/auth",
		},
		CookieName: "cookie_test",
		Lifetime:   time.Second * time.Duration(10),
		stateMap:   ttlmap.NewWithTTL(time.Duration(time.Second * 10)),
	}

	// Should redirect vanilla request to login url
	req := newHTTPRequest("foo")
	res, _ := httpRequest(req, nil)
	if res.StatusCode != 307 {
		t.Error("Vanilla request should be redirected with 307, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "test.com" || fwd.Path != "/auth" {
		t.Error("Vanilla request should be redirected to login URL, got:", fwd)
	}

	// Should handle invalid cookie
	req = newHTTPRequest("foo")

	c := fw.MakeCookie(req, fw.CookieName, "non-existing-secret-key")
	parts := strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Request with invalid cookie should not be authorized, got:", res.StatusCode)
	}

	// Should handle non existing secret key
	req = newHTTPRequest("foo")
	c = fw.MakeCookie(req, fw.CookieName, "non-existing-secret-key")
	res, _ = httpRequest(req, c)
	if res.StatusCode != 307 {
		t.Error("Request with non existing secret key should be redirected to auth, got:", res.StatusCode)
	}

	// Configure the token in the stateMap
	secureKey, err := getSecureKey()
	if err != nil {
		t.Error("Expected the secret key to generate but got", err)
	}
	pseudoToken := getJWT(t, "test@example.com")
	fw.stateMap.Add(secureKey, pseudoToken)

	// Should validate email
	req = newHTTPRequest("foo")
	c = fw.MakeCookie(req, fw.CookieName, secureKey)
	fw.Domain = []string{"test.com"}
	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Request with an email for unauthorized domain should shouldn't be authorised", res.StatusCode)
	}

	// Should allow valid request email
	req = newHTTPRequest("foo")
	c = fw.MakeCookie(req, fw.CookieName, secureKey)
	fw.Domain = []string{}

	res, _ = httpRequest(req, c)
	if res.StatusCode != 200 {
		t.Error("Valid request should be allowed, got:", res.StatusCode)
	}

	// Should pass through user
	bearerTokens := res.Header["X-Forwarded-Access-Token"]
	if len(bearerTokens) != 1 {
		t.Error("Valid request missing X-Forwarded-Access-Token header")
	} else if bearerTokens[0] != pseudoToken {
		t.Error("X-Forwarded-Access-Token should match test token, got:", bearerTokens[0])
	}

	// Validate that tokens expire
	shortLivedSecureKey, err := getSecureKey()
	if err != nil {
		t.Error("Expected the secret key to generate but got", err)
	}
	fw.stateMap.AddWithTTL(shortLivedSecureKey, pseudoToken, time.Second)

	req = newHTTPRequest("foo")
	c = fw.MakeCookie(req, fw.CookieName, shortLivedSecureKey)
	fw.Domain = []string{}
	res, _ = httpRequest(req, c)
	if res.StatusCode != 200 {
		t.Error("Valid request should be allowed before key expiry, got:", res.StatusCode)
	}

	<-time.After(time.Duration(time.Second * 2))

	req = newHTTPRequest("foo")
	c = fw.MakeCookie(req, fw.CookieName, shortLivedSecureKey)
	fw.Domain = []string{}
	res, _ = httpRequest(req, c)
	if res.StatusCode != 307 {
		t.Error("Valid request should be disallowed and redirected to the authentication when key expired, got:", res.StatusCode)
	}
}

func TestCallback(t *testing.T) {

	fw = &ForwardAuth{
		Path:         "_oauth",
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "test.com",
			Path:   "/auth",
		},
		CSRFCookieName: "csrf_test",
		stateMap:       ttlmap.NewWithTTL(time.Duration(time.Second * 10)),
	}

	// Setup valid user token server
	tokenValidUserServerHandler := &TokenValidUserServerHandler{
		t: t,
	}
	tokenValidUserServer := httptest.NewServer(tokenValidUserServerHandler)
	defer tokenValidUserServer.Close()
	tokenValidUserURL, _ := url.Parse(tokenValidUserServer.URL)

	// Setup user server
	userServerHandler := &UserServerHandler{}
	userServer := httptest.NewServer(userServerHandler)
	defer userServer.Close()
	userURL, _ := url.Parse(userServer.URL)
	fw.UserURL = userURL

	// Should pass auth response request to callback
	req := newHTTPRequest("_oauth")
	res, _ := httpRequest(req, nil)
	if res.StatusCode != 401 {
		t.Error("Auth callback without cookie shouldn't be authorised, got:", res.StatusCode)
	}

	// Should catch invalid csrf cookie
	req = newHTTPRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
	c := fw.MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = httpRequest(req, c)
	if res.StatusCode != 401 {
		t.Error("Auth callback with invalid cookie shouldn't be authorised, got:", res.StatusCode)
	}

	// Should redirect valid request
	fw.TokenURL = tokenValidUserURL

	req = newHTTPRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
	c = fw.MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ = httpRequest(req, c)
	if res.StatusCode != 307 {
		t.Error("Valid callback should be allowed, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "redirect" || fwd.Path != "" {
		t.Error("Valid request should be redirected to return url, got:", fwd)
	}
}

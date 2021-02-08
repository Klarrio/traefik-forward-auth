package wellknownopenidconfiguration

import (
	"fmt"
	"github.com/Klarrio/traefik-forward-auth/util"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestGetLoginURL(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "example.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	oidcApi := NewWellKnownOpenIDConfiguration(
		util.CreateLogger("debug", "text"),
		&OIDCClientCredentials{
			ClientID:     "idtest",
			ClientSecret: "sectest",
		},
		"scopetest",
		"consent select_account")

	oidcApi.AuthorizationEndpoint = "https://test.com/auth"
	oidcApi.TokenEndpoint = "https://test.com/token"
	oidcApi.UserInfoEndpoint = "https://test.com/user"
	oidcApi.Resolve()

	// Check url
	uri, err := url.Parse(oidcApi.GetLoginURL("nonce", "http://example.com/hello", "http://example.com/_oauth"))
	if err != nil {
		t.Error("Error parsing login url:", err)
	}
	if uri.Scheme != "https" {
		t.Error("Expected login Scheme to be \"https\", got:", uri.Scheme)
	}
	if uri.Host != "test.com" {
		t.Error("Expected login Host to be \"test.com\", got:", uri.Host)
	}
	if uri.Path != "/auth" {
		t.Error("Expected login Path to be \"/auth\", got:", uri.Path)
	}

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"prompt":        []string{"consent select_account"},
		"state":         []string{"nonce:http://example.com/hello"},
	}
	if !reflect.DeepEqual(qs, expectedQs) {
		t.Error("Incorrect login query string:")
		qsDiff(expectedQs, qs)
	}
}

// TODO
// func TestExchangeCode(t *testing.T) {
// }

// TODO
// func TestGetUser(t *testing.T) {
// }

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

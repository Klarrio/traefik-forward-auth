package wellknownopenidconfiguration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

// TokenValidationEndpointCredentials represents token introspection credentials.
type TokenValidationEndpointCredentials struct {
	Username string
	Password string
}

// MaybeAddBasicAuth adds the Authentication header to the request, if username and password are not empty strings.
func (t *TokenValidationEndpointCredentials) MaybeAddBasicAuth(request *http.Request) bool {
	if t.Username != "" && t.Password != "" {
		auth := t.Username + ":" + t.Password
		request.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		return true
	}
	return false
}

// WellKnownOpenIDConfiguration represents the well known OpenID configuration
// fetched from the realm .well-known/openid-configuration HTTP endpoint.
type WellKnownOpenIDConfiguration struct {
	logger                     logrus.FieldLogger
	credentials                *TokenValidationEndpointCredentials
	Issuer                     string `json:"issuer"`
	AuthorizationEndpoint      string `json:"authorization_endpoint"`
	TokenEndpoint              string `json:"token_endpoint"`
	TokenIntrospectionEndpoint string `json:"token_introspection_endpoint"`
	EndSessionEndpoint         string `json:"end_session_endpoint"`
	UserInfoEndpoint           string `json:"userinfo_endpoint"`
	JWKSURI                    string `json:"jwks_uri"`
}

func NewWellKnownOpenIDConfiguration(logger logrus.FieldLogger, credentials *TokenValidationEndpointCredentials) *WellKnownOpenIDConfiguration {
	return &WellKnownOpenIDConfiguration{
		logger:      logger,
		credentials: credentials,
	}
}

// TokenValidationResult represents the token validation result.
// When there was a problem validating the token, the value of Error will be non-empty.
// Active equal to false means the token is expired.
type TokenValidationResult struct {
	Active           bool   `json:"active"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ToError returns an error if Error was not empty, otherwise returns nil.
func (t *TokenValidationResult) ToError() error {
	if len(t.Error) > 0 {
		return fmt.Errorf("%s: %s", t.Error, t.ErrorDescription)
	}
	return nil
}

// ValidateToken validates given token.
func (w *WellKnownOpenIDConfiguration) ValidateToken(token string) (*TokenValidationResult, error) {

	form := url.Values{}
	form.Add("token", token)
	requestBody := form.Encode()

	request, requestError := http.NewRequest("POST", w.TokenIntrospectionEndpoint, bytes.NewBuffer([]byte(requestBody)))
	if requestError != nil {
		return nil, requestError
	}

	request.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestBody)))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	authHeaderAdded := w.credentials.MaybeAddBasicAuth(request)

	w.logger.Warn("token validation", "with-auth", authHeaderAdded, "request-body-length", len(requestBody), "uri", w.TokenIntrospectionEndpoint)

	httpClient := &http.Client{}
	response, responseEError := httpClient.Do(request)
	if responseEError != nil {
		return nil, responseEError
	}
	responseBytes, responseBodyError := ioutil.ReadAll(response.Body)
	if responseBodyError != nil {
		return nil, responseBodyError
	}
	result := &TokenValidationResult{}
	if jsonError := json.Unmarshal(responseBytes, result); jsonError != nil {
		return nil, jsonError
	}
	return result, result.ToError()
}

// ResolveWellKnownOpenIDConfiguration resolves the well known open ID configuration for a given realm.
func ResolveWellKnownOpenIDConfiguration(logger logrus.FieldLogger, realmURI, username, password string) (*WellKnownOpenIDConfiguration, error) {
	request, requestError := http.NewRequest("GET", fmt.Sprintf("%s/.well-known/openid-configuration", realmURI), nil)
	if requestError != nil {
		return nil, requestError
	}
	httpClient := &http.Client{}
	response, responseEError := httpClient.Do(request)
	if responseEError != nil {
		return nil, responseEError
	}
	responseBytes, responseBodyError := ioutil.ReadAll(response.Body)
	if responseBodyError != nil {
		return nil, responseBodyError
	}
	cfg := &WellKnownOpenIDConfiguration{
		logger: logger,
		credentials: &TokenValidationEndpointCredentials{
			Username: username,
			Password: password,
		},
	}
	if jsonError := json.Unmarshal(responseBytes, cfg); jsonError != nil {
		return nil, jsonError
	}
	return cfg, nil
}

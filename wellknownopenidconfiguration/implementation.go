package wellknownopenidconfiguration

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

// OIDCClientCredentials represents the OIDC client credentials that are required to communicate with the oidc server.
type OIDCClientCredentials struct {
	ClientID     string
	ClientSecret string
}

// MaybeAddBasicAuth adds the Authentication header to the request, if username and password are not empty strings.
func (t *OIDCClientCredentials) MaybeAddBasicAuth(request *http.Request) bool {
	if t.ClientID != "" && t.ClientSecret != "" {
		auth := t.ClientID + ":" + t.ClientSecret
		request.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		return true
	}
	return false
}

// WellKnownOpenIDConfiguration represents the well known OpenID configuration
// fetched from the realm .well-known/openid-configuration HTTP endpoint.
type WellKnownOpenIDConfiguration struct {
	logger                     logrus.FieldLogger
	credentials                *OIDCClientCredentials
	loginURL				   *url.URL
	tokenURL                   *url.URL
	userURL                    *url.URL
	scope                      string
	prompt                     string
	insecureCertificates 	   bool
	Issuer                     string `json:"issuer"`
	AuthorizationEndpoint      string `json:"authorization_endpoint"`
	TokenEndpoint              string `json:"token_endpoint"`
	TokenIntrospectionEndpoint string `json:"token_introspection_endpoint"`
	EndSessionEndpoint         string `json:"end_session_endpoint"`
	UserInfoEndpoint           string `json:"userinfo_endpoint"`
	JWKSURI                    string `json:"jwks_uri"`
}

func NewWellKnownOpenIDConfiguration(logger logrus.FieldLogger, credentials *OIDCClientCredentials, scope string, prompt string) *WellKnownOpenIDConfiguration {
	return &WellKnownOpenIDConfiguration{
		logger:      logger,
		credentials: credentials,
		scope: scope,
		prompt: prompt,
	}
}

/**
 * Resolves its properties based on the public OIDC-based properties
 */
func (w *WellKnownOpenIDConfiguration) Resolve() {
	loginURL, err := url.Parse(w.AuthorizationEndpoint)
	if err != nil {
		log.Fatal("unable to parse login url: ", err)
	}

	tokenURL, err := url.Parse(w.TokenEndpoint)
	if err != nil {
		log.Fatal("unable to parse token url: ", err)
	}
	userURL, err := url.Parse(w.UserInfoEndpoint)
	if err != nil {
		log.Fatal("unable to parse user url: ", err)
	}

	w.loginURL = loginURL
	w.tokenURL = tokenURL
	w.userURL = userURL
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

// TokenRefreshResult represents the token refresh result.
// When there was a problem refreshing the token, the value of Error will be non-empty.
// Otherwise, the call was success.
type TokenRefreshResult struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
}

// ToError returns an error if Error was not empty, otherwise returns nil.
func (t *TokenRefreshResult) ToError() error {
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

	w.logger.Debug("token validation", " with-auth:[", authHeaderAdded, "] request-body-length:[", len(requestBody), "] uri:[", w.TokenIntrospectionEndpoint, "]")

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

// GetLoginURL gets the login URL for the service.
func (w *WellKnownOpenIDConfiguration) GetLoginURL(nonce string, returnUrl string, redirectUrl string) string {
	state := fmt.Sprintf("%s:%s", nonce, returnUrl)

	q := url.Values{}
	q.Set("client_id", w.credentials.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", w.scope)
	if w.prompt != "" {
		q.Set("prompt", w.prompt)
	}
	q.Set("redirect_uri", redirectUrl)
	q.Set("state", state)

	var u = *w.loginURL
	u.RawQuery = q.Encode()

	return u.String()
}

// LogOut logs out given token.
func (w *WellKnownOpenIDConfiguration) LogOut(token string) error {

	uriString := fmt.Sprintf("%s?client_id=%s&id_token_hint=%s", w.EndSessionEndpoint, w.credentials.ClientID, token)

	request, requestError := http.NewRequest("GET", uriString, nil)
	if requestError != nil {
		return requestError
	}
	//authHeaderAdded := w.credentials.MaybeAddBasicAuth(request)

	w.logger.Warn("token log out", "uri", uriString)

	httpClient := &http.Client{}
	response, responseEError := httpClient.Do(request)
	if responseEError != nil {
		return responseEError
	}
	responseBytes, responseBodyError := ioutil.ReadAll(response.Body)
	if responseBodyError != nil {
		return responseBodyError
	}

	w.logger.Warn("token logged out", "response", string(responseBytes))

	return nil
}

// TokenRefresh handles token refresh.
func (w *WellKnownOpenIDConfiguration) TokenRefresh(refreshToken string) (*TokenRefreshResult, error) {
	form := url.Values{}
	form.Add("client_id", w.credentials.ClientID)
	form.Add("client_secret", w.credentials.ClientSecret)
	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", refreshToken)
	form.Add("scope", w.scope)
	requestBody := form.Encode()

	request, requestError := http.NewRequest("POST", w.TokenEndpoint, bytes.NewBuffer([]byte(requestBody)))
	if requestError != nil {
		return nil, requestError
	}

	request.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestBody)))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	authHeaderAdded := w.credentials.MaybeAddBasicAuth(request)

	w.logger.Debug("[token refresh] with-auth:[", authHeaderAdded, "] request-body-length:[", len(requestBody), "] uri:[", w.TokenEndpoint, "]")

	httpClient := &http.Client{}
	response, responseEError := httpClient.Do(request)
	if responseEError != nil {
		return nil, responseEError
	}
	responseBytes, responseBodyError := ioutil.ReadAll(response.Body)
	if responseBodyError != nil {
		return nil, responseBodyError
	}
	result := &TokenRefreshResult{}
	if jsonError := json.Unmarshal(responseBytes, result); jsonError != nil {
		return nil, jsonError
	}
	return result, result.ToError()
}

// ExchangeCode exchanges the authorization code for the token.
func (w *WellKnownOpenIDConfiguration) ExchangeCode(r *http.Request, code string, redirectURI string) (*Token, error) {
	form := url.Values{}
	form.Set("client_id", w.credentials.ClientID)
	form.Set("client_secret", w.credentials.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	// allow insecure certificates when enabled
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: w.insecureCertificates},
		},
	}

	token := &Token{}

	res, err := client.PostForm(w.tokenURL.String(), form)
	if err != nil {
		return token, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(token)

	return token, err
}

// VerifyAccess checks whether access is allowed to all resources of the client using the UMA protocol.
// https://www.keycloak.org/docs/4.8/authorization_services/index.html#_service_obtaining_permissions
func (w *WellKnownOpenIDConfiguration) VerifyAccess(token string) (bool, error) {
	// allow insecure certificates when enabled
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: w.insecureCertificates},
		},
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	data.Set("audience", w.credentials.ClientID)
	encoded := data.Encode()

	req, err := http.NewRequest(http.MethodPost, w.tokenURL.String(), strings.NewReader(encoded))
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(encoded)))
	res, err := client.Do(req)

	// status code is 403 when not allowed by authorization server
	isAllowedAccess := err == nil && res.StatusCode == 200

	defer res.Body.Close()

	return isAllowedAccess, err
}

// Get user with token

// User is the intermediate user object used when fetching
// user info from the authentication service.
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Hd       string `json:"hd"`
}

// GetUser retries the user info for the given token from the authentication service.
func (w *WellKnownOpenIDConfiguration) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: w.insecureCertificates},
		},
	}
	req, err := http.NewRequest("GET", w.userURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return user, err
}

// ResolveWellKnownOpenIDConfiguration resolves the well known open ID configuration for a given realm.
func ResolveWellKnownOpenIDConfiguration(logger logrus.FieldLogger, realmURI, username, password string, prompt string, scope string, insecureCertificates bool) (*WellKnownOpenIDConfiguration, error) {
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
		insecureCertificates: insecureCertificates,
		prompt: prompt,
		scope: scope,
		credentials: &OIDCClientCredentials{
			ClientID:     username,
			ClientSecret: password,
		},
	}
	if jsonError := json.Unmarshal(responseBytes, cfg); jsonError != nil {
		return nil, jsonError
	}

	cfg.Resolve()

	return cfg, nil
}

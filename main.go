package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Klarrio/traefik-forward-auth/session"
	"github.com/Klarrio/traefik-forward-auth/util"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"

	oidc "github.com/Klarrio/traefik-forward-auth/wellknownopenidconfiguration"
)

var (
	oidcApi          *oidc.WellKnownOpenIDConfiguration
	sessionInventory *session.Inventory
	fw               *ForwardAuth
	log              logrus.FieldLogger
)

const (
	// AcceptedRolesRequestHeader name of the request header which indicates the accepted roles
	acceptedRolesRequestHeader = "X-Forward-Auth-Accepted-Roles"
)

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := log.WithFields(logrus.Fields{
		"SourceIP": r.Header.Get("X-Forwarded-For"),
	})
	logger.WithFields(logrus.Fields{
		"Headers": r.Header,
	}).Debug("Handling request")

	// Set security-related headers on the potential response
	if fw.Secure {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
	}

	// Parse uri
	uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		logger.Error("Error parsing X-Forwarded-Uri, ", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Handle callback
	if uri.Path == fw.Path {
		logger.Debug("Passing request to auth callback")
		handleCallback(w, r, uri.Query(), logger)
		return
	}

	isHandled, sessionKey := getValidCookieOrHandleRedirect(fw.CookieName, uri.Path, logger, w, r)
	if isHandled == handled(true) {
		// cookie did not validate or there was no cookie, it's already handled
		return
	}

	sessionMetadata, sessionExists := sessionInventory.SessionMetadata(sessionKey)
	if !sessionExists {
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	if time.Now().After(sessionMetadata.ExpiresAt) {
		logger.WithFields(logrus.Fields{
			"secure-key": sessionKey,
			"expired-at": sessionMetadata.ExpiresAt.String(),
			"now":        time.Now().String(),
		}).Debug("token for secure key expired, redirecting to auth")
		endSession(sessionKey, w, r)
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	accessToken, rawAccessToken := sessionInventory.EnsureValidAccessToken(sessionKey, fw.tokenMinValidity)
	if accessToken == nil {
		logger.WithField("session key", sessionKey).Info("Ending session because no valid access token available")
		endSession(sessionKey, w, r) // end the session when the access token can't be refreshed
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	// Handle logout:
	if fw.LogoutPath != "" && uri.Path == fw.LogoutPath {
		logger.WithFields(logrus.Fields{
			"logout-path":      fw.LogoutPath,
			"post-redirect-to": fw.PostLogoutPath,
		}).Info("handling logout ")
		endSession(sessionKey, w, r)
		if logoutError := oidcApi.LogOut(rawAccessToken); logoutError != nil {
			logger.WithFields(logrus.Fields{
				"logout-error": logoutError,
			}).Error("error while logging out")
		}
		r.Header.Set("X-Forwarded-Uri", fw.PostLogoutPath)
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	// Validate user
	if !fw.ValidateEmail(accessToken.Email) {
		logger.WithFields(logrus.Fields{
			"email": accessToken.Email,
		}).Error("Invalid email in stored token")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate whether the access token contains one of the request's accepted roles, if available in request header
	acceptedRolesParam := r.Header.Get(acceptedRolesRequestHeader)
	if acceptedRolesParam != "" {
		logger.Debugf("validating accepted roles for request: %s", acceptedRolesParam)
		acceptedRoles := strings.Split(acceptedRolesParam, ",")
		tokenClaims := make(map[string]interface{})
		claimsBytes, err := oidc.PayloadBytesFromJwt(rawAccessToken)
		if err != nil {
			logger.Error("unable to parse token claims")
			http.Error(w, "Internal server error", 500)
			return
		}
		if err := json.Unmarshal(claimsBytes, &tokenClaims); err != nil {
			logger.Error("unable to parse token claims")
			http.Error(w, "Internal server error", 500)
			return
		}
		
		accessTokenRolesString, hasRoles := tokenClaims[fw.AccessTokenRolesField].(string)
		if !hasRoles {
			logger.Info("access token has no roles defined. not authorized.")
			http.Error(w, "Not authorized", 401)
			return
		}	

		logger.Debugf("access token roles: %s", accessTokenRolesString)
		accessTokenRoles := strings.Split(accessTokenRolesString, fw.AccessTokenRolesDelimiter)

		if !hasRequiredRole(accessTokenRoles, acceptedRoles) {
			logger.Info("access token does not have one of the accepted roles")
			http.Error(w, "Not authorized", 401)
			return
		}
	}

	w.Header().Set("X-Forwarded-Access-Token", rawAccessToken)
	w.WriteHeader(200)
}

// Verifies whether one of the acceptedRoles exist in the accessTokenRoles
func hasRequiredRole(accessTokenRoles []string, acceptedRoles []string) bool {
	for _, tokenRole := range accessTokenRoles {
		for _, acceptedRole := range acceptedRoles {
			if tokenRole == acceptedRole {
				return true
			}
		}
	}

	return false
}

// Authenticate user after they have come back from oidc
func handleCallback(w http.ResponseWriter, r *http.Request, qs url.Values,
	logger logrus.FieldLogger) {
	// Check for CSRF cookie
	csrfCookie, err := r.Cookie(fw.CSRFCookieName)
	if err != nil {
		logger.Warn("Missing csrf cookie")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate state
	state := qs.Get("state")
	valid, redirect, err := fw.ValidateCSRFCookie(csrfCookie, state)
	if !valid {
		logger.WithFields(logrus.Fields{
			"csrf":  csrfCookie.Value,
			"state": state,
		}).Warn("Error validating csrf cookie: ", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, fw.ClearCSRFCookie(r))

	logger.WithFields(logrus.Fields{
		"state": state,
	}).Debug("About to exchange for code: ", err)

	// Exchange code for token
	token, err := oidcApi.ExchangeCode(r, qs.Get("code"), fw.redirectURI(r))

	logger.WithFields(logrus.Fields{
		"exchange-result": token,
		"state":           state,
	}).Debug("Exchange code result: ", err)

	if err != nil {
		logger.Error("Code exchange failed with: ", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	if fw.UMAAuthorization {
		isAllowedAccess, err := oidcApi.VerifyAccess(token.AccessToken)
		if err != nil {
			logger.Error("Access verification failed with: ", err)
			http.Error(w, "Service unavailable", 503)
			return
		}
		if !isAllowedAccess {
			logger.Info("Not authorized")
			http.Error(w, "Not authorized", 401)
			return
		}
	}

	err = startSession(w, r, token, logger)
	if err != nil {
		http.Error(w, "Internal server error", 500)
		return
	}

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

type handled bool

func startSession(w http.ResponseWriter, r *http.Request, token *oidc.Token, logger logrus.FieldLogger) error {
	bearerToken, err := oidc.BearerTokenFromWire(token.AccessToken)
	if err != nil {
		logger.Error("Error parsing bearer token '", token, "': ", err)
		return errors.New(fmt.Sprintf("Failed to fetch secure key: %s", err))
	}

	expiry := fw.cookieExpiry()

	sessionKey, err := getSecureKey()
	if err != nil {
		logger.Error("Failed to fetch secure key: ", err)
		return errors.New(fmt.Sprintf("Failed to fetch secure key: %s", err))
	}

	sessionInventory.StoreSession(sessionKey, token, expiry)

	logger.WithFields(logrus.Fields{
		"expire-at": expiry.String(),
		"now":       time.Now().String(),
	}).Debug("setting state cookie with expiry")

	// Generate cookies
	sessionAuthCookie := fw.MakeSessionAuthCookie(r, sessionKey)
	sessionInfoCookie := fw.MakeSessionInfoCookie(r, bearerToken.Name)
	http.SetCookie(w, sessionAuthCookie)
	http.SetCookie(w, sessionInfoCookie)

	logger.WithFields(logrus.Fields{
		"bearer-token-length": len(token.AccessToken),
		"email-from-token":    bearerToken.Email,
	}).Info("Generated auth cookie")

	return nil
}

func endSession(sessionKey string, w http.ResponseWriter, r *http.Request) {
	sessionInventory.RemoveSession(sessionKey)
	http.SetCookie(w, fw.ClearCookie(r, fw.CookieName))
	http.SetCookie(w, fw.ClearCookie(r, fw.InfoCookieName))
}

func getValidCookieOrHandleRedirect(cookieName, uriPath string, logger *logrus.Entry, w http.ResponseWriter, r *http.Request) (handled, string) {
	// Get the cookie
	var content string
	c, err := r.Cookie(cookieName)
	if err != nil {
		redirectToAuth(uriPath, logger, w, r)
		return handled(true), content
	}

	// Validate cookie
	valid, content, err := fw.ValidateSessionAuthCookie(r, c)
	if !valid {
		logger.Error("Invalid cookie: ", err)
		http.Error(w, "Not authorized", 401)
		return handled(true), content
	}
	return handled(false), content
}

func redirectToAuth(uriPath string, logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	nonce, err := fw.Nonce()
	if err != nil {		logger.Error("Error generating nonce: ", err)
		http.Error(w, "Service unavailable", 503)
		return
	}
	// Set the CSRF cookie
	http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirecting to oidc login")
	logger.Debug("uri.Path was ", uriPath)
	logger.Debug("fw.Path was ", fw.Path)
	// Forward them on
	returnUrl := fw.returnURL(r)
	redirectUrl := fw.redirectURI(r)
	http.Redirect(w, r, oidcApi.GetLoginURL(nonce, returnUrl, redirectUrl), http.StatusTemporaryRedirect)
}

// Main
func main() {
	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	secret := flag.String("secret", "", "*Secret used for signing (required)")
	authHost := flag.String("auth-host", "", "Central auth login")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC Issuer URL (required)")
	clientID := flag.String("client-id", "", "Client ID (required)")
	clientSecret := flag.String("client-secret", "", "Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	infoCookieName := flag.String("info-cookie-name", "_forward_auth_info", "Info Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "Deprecated")
	secure := flag.Bool("secure", true, "Use secure configuration")
	insecureCertificates := flag.Bool("insecure-certificates", false, "Allow insecure certificates")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")
	umaAuthorization := flag.Bool("uma-authorization", false, "whether UMA-based authorization will be performed")
	logLevel := flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error, fatal, panic")
	logFormat := flag.String("log-format", "text", "Log format: text, json, pretty")
	tokenValidatorEnabled := flag.Bool("token-validator-enabled", true, "Whether the access token should be validated on each request")
	tokenMinValiditySeconds := flag.Int("token-min-validity-seconds", 10, "when the access token isn't valid for x seconds anymore, it will be refreshed on a request")
	accessTokenRolesField := flag.String("access-token-roles-field", "", "Field name within the OIDC access token which contains the roles")
	accessTokenRolesDelimiter := flag.String("access-token-roles-delimiter", "", "which delimiter is being used in the OIDC access token to define multiple roles")

	scope := flag.String("scope", "openid profile email", "Requested scopes")
	logoutPath := flag.String("logout-path", "", "Logout path, if empty, logout not enabled")
	postLogoutPath := flag.String("post-logout-path", "", "Path to redirect to after logout")

	flag.Parse()

	// Setup logger
	log = util.CreateLogger(*logLevel, *logFormat)

	// Setup insecure http calls if requested
	if *insecureCertificates {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Backwards compatibility
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}

	// Check for show stopper errors
	if *clientID == "" || *clientSecret == "" || *secret == "" || *oidcIssuer == "" {
		log.Fatal("client-id, client-secret, secret and oidc-issuer must all be set")
	}

	// Parse lists
	var cookieDomains []CookieDomain
	if *cookieDomainList != "" {
		for _, d := range strings.Split(*cookieDomainList, ",") {
			cookieDomain := NewCookieDomain(d)
			cookieDomains = append(cookieDomains, *cookieDomain)
		}
	}

	var domain []string
	if *domainList != "" {
		domain = strings.Split(*domainList, ",")
	}
	var whitelist []string
	if *emailWhitelist != "" {
		whitelist = strings.Split(*emailWhitelist, ",")
	}

	oidcConfig, err := oidc.ResolveWellKnownOpenIDConfiguration(log, *oidcIssuer, *clientID, *clientSecret, *prompt, *scope, *insecureCertificates)
	if err != nil {
		log.Fatal("unable to resolve .well-known/openid-configuration: ", err)
	}
	oidcApi = oidcConfig

	// Setup
	sessionInventory = session.NewInventory(oidcApi, *tokenValidatorEnabled, log)
	fw = &ForwardAuth{
		Path:     fmt.Sprintf("/%s", *path),
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		InfoCookieName: *infoCookieName,
		CookieDomains:  cookieDomains,

		Secure: *secure,

		Domain:    domain,
		Whitelist: whitelist,

		UMAAuthorization: *umaAuthorization,

		tokenMinValidity:             time.Second * time.Duration(*tokenMinValiditySeconds),
		PostLogoutPath:               *postLogoutPath,
		LogoutPath:                   *logoutPath,

		AccessTokenRolesField:		  *accessTokenRolesField,
		AccessTokenRolesDelimiter:    *accessTokenRolesDelimiter,
	}

	// Attach handler
	http.HandleFunc("/", handler)

	// Start
	fwJsonConf, _ := json.Marshal(fw)
	log.Debug("FW config: ", string(fwJsonConf))
	sessionInventoryJsonConf, _ := json.Marshal(sessionInventory)
	log.Debug("Session inventory config: ", string(sessionInventoryJsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}

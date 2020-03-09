package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"

	"github.com/Klarrio/traefik-forward-auth/ttlmap"
	"github.com/Klarrio/traefik-forward-auth/wellknownopenidconfiguration"
)

var (
	fw  *ForwardAuth
	log logrus.FieldLogger
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

	isHandled, secureKey := getValidCookieOrHandleRedirect(fw.CookieName, uri.Path, logger, w, r)
	if isHandled == handled(true) {
		// cookie did not validate or there was no cookie, it's already handled
		return
	}

	mapItem, hadItem := fw.stateMap.Get(secureKey)
	if !hadItem {
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	if time.Now().After(mapItem.ExpiresAt()) {
		logger.WithFields(logrus.Fields{
			"secure-key": secureKey,
			"expired-at": mapItem.ExpiresAt().String(),
			"now":        time.Now().String(),
		}).Debug("token for secure key expired, redirecting to auth")
		fw.stateMap.Remove(secureKey) // cleanup
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	// We have the token available and we could resolve the map item, item not expired yet:
	var storedToken *Token
	switch tval := mapItem.Value().(type) {
	case *Token:
		storedToken = tval
	default:
		logger.Error("Expected the map item to contain a string token but received ", tval)
		http.Error(w, "Internal server error", 500)
		return
	}

	// Handle logout:
	if fw.LogoutPath != "" && uri.Path == fw.LogoutPath {
		logger.WithFields(logrus.Fields{
			"logout-path":      fw.LogoutPath,
			"post-redirect-to": fw.PostLogoutPath,
		}).Info("handling logout ")
		fw.stateMap.Remove(secureKey)
		http.SetCookie(w, fw.ClearCookie(r, fw.CookieName))
		if logoutError := fw.wellKnownOpenIDConfiguration.LogOut(fw.ClientID, storedToken.AccessToken); logoutError != nil {
			logger.WithFields(logrus.Fields{
				"logout-error": logoutError,
			}).Error("error while logging out")
		}
		r.Header.Set("X-Forwarded-Uri", fw.PostLogoutPath)
		redirectToAuth(uri.Path, logger, w, r)
		return
	}

	// Handle token refresh:
	if fw.RefreshPath != "" && uri.Path == fw.RefreshPath {
		logger.WithFields(logrus.Fields{
			"refresh-path": fw.RefreshPath,
		}).Info("handling token refresh ")
		fw.stateMap.Remove(secureKey)
		http.SetCookie(w, fw.ClearCookie(r, fw.CookieName))

		refreshedToken, refreshError := fw.wellKnownOpenIDConfiguration.TokenRefresh(fw.ClientID, fw.ClientSecret, storedToken.RefreshToken, fw.Scope)
		if refreshError != nil {
			logger.WithFields(logrus.Fields{
				"refresh-token-error": refreshError,
			}).Error("error while refreshing token")
			http.Error(w, "Internal server error", 500)
			return
		}

		refreshedBearerToken, err := bearerTokenFromWire(refreshedToken.AccessToken)
		if err != nil {
			logger.Error("Error parsing refreshed token '", refreshedToken, "': ", err)
			http.Error(w, "Bad request", 400)
			return
		}

		exp := refreshedBearerToken.ExpTime()
		fw.stateMap.AddWithTTL(secureKey, &Token{
			AccessToken:  refreshedToken.AccessToken,
			TokenType:    refreshedToken.TokenType,
			RefreshToken: refreshedToken.RefreshToken,
			ExpiresIn:    refreshedToken.ExpiresIn,
		}, exp.Sub(time.Now()))

		logger.Info("Updated TTL map with refreshed token '", refreshedToken, "', setting the cookie")

		// Generate cookie
		http.SetCookie(w, fw.MakeCookieWithExpiry(r, fw.CookieName, secureKey, exp))

		logger.Info("Redirecting after token refresh")

		http.Redirect(w, r, fw.redirectBase(r), http.StatusTemporaryRedirect)
		return

	}

	bearerToken, err := bearerTokenFromWire(storedToken.AccessToken)
	if err != nil {
		logger.Error("Error parsing stored token, reason ", err)
		http.Error(w, "Internal server error", 500)
		return
	}

	// Validate user
	if !fw.ValidateEmail(bearerToken.Email) {
		logger.WithFields(logrus.Fields{
			"email": bearerToken.Email,
		}).Error("Invalid email in stored token")
		http.Error(w, "Not authorized", 401)
		return
	}

	if fw.tokenValidatorEnabled {
		validationResult, err := fw.wellKnownOpenIDConfiguration.ValidateToken(storedToken.AccessToken)
		var requirelogin bool
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Error("Failed to validate token")
			requirelogin = true
		} else {
			if !validationResult.Active {
				logger.WithFields(logrus.Fields{
					"result": validationResult,
				}).Error("Token invalid, redirecting to auth")
				requirelogin = true
			}
		}
		if requirelogin {
			fw.stateMap.Remove(secureKey)
			http.SetCookie(w, fw.ClearCookie(r, fw.CookieName))
			redirectToAuth(uri.Path, logger, w, r)
			return
		}
		// Valid request
		logger.WithFields(logrus.Fields{
			"result": validationResult,
		}).Debug("Allowing valid request")
	} else {
		// Valid request
		logger.WithFields(logrus.Fields{
			"validator-disabled": true,
		}).Debug("Allowing valid request")
	}

	// Validate whether the access token contains one of the request's accepted roles, if available in request header
	acceptedRolesParam := r.Header.Get(acceptedRolesRequestHeader)
	if acceptedRolesParam != "" {
		logger.Debugf("validating accepted roles for request: %s", acceptedRolesParam)
		acceptedRoles := strings.Split(acceptedRolesParam, ",")
		tokenClaims := make(map[string]interface{})
		claimsBytes, err := payloadBytesFromJwt(storedToken.AccessToken)
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

	w.Header().Set("X-Forwarded-Access-Token", storedToken.AccessToken)
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
	token, err := fw.ExchangeCode(r, qs.Get("code"))

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
		isAllowedAccess, err := fw.VerifyAccess(token.AccessToken)
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

	bearerToken, err := bearerTokenFromWire(token.AccessToken)
	if err != nil {
		logger.Error("Error parsing bearer token '", token, "': ", err)
		http.Error(w, "Bad request", 400)
		return
	}

	secureKey, err := getSecureKey()
	if err != nil {
		logger.Error("Failed to fetch secure key: ", err)
		http.Error(w, "Internal server error", 500)
		return
	}

	exp := bearerToken.ExpTime()
	fw.stateMap.AddWithTTL(secureKey, token, exp.Sub(time.Now()))

	logger.WithFields(logrus.Fields{
		"expire-at": exp.String(),
		"now":       time.Now().String(),
	}).Debug("setting state cookie with expiry")

	// Generate cookie
	http.SetCookie(w, fw.MakeCookieWithExpiry(r, fw.CookieName, secureKey, exp))

	logger.WithFields(logrus.Fields{
		"bearer-token-length": len(token.AccessToken),
		"email-from-token":    bearerToken.Email,
		"handler":             "handleCallback",
	}).Info("Generated auth cookie")

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

type handled bool

func getValidCookieOrHandleRedirect(cookieName, uriPath string, logger *logrus.Entry, w http.ResponseWriter, r *http.Request) (handled, string) {
	// Get the cookie
	var content string
	c, err := r.Cookie(cookieName)
	if err != nil {
		redirectToAuth(uriPath, logger, w, r)
		return handled(true), content
	}

	// Validate cookie
	valid, content, err := fw.ValidateCookie(r, c)
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
	if err != nil {
		logger.Error("Error generating nonce: ", err)
		http.Error(w, "Service unavailable", 503)
		return
	}
	// Set the CSRF cookie
	http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirecting to oidc login")
	logger.Debug("uri.Path was ", uriPath)
	logger.Debug("fw.Path was ", fw.Path)
	// Forward them on
	http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)
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
	tokenValidatorEnabled := flag.Bool("token-validator-enabled", true, "Log format: text, json, pretty")
	accessTokenRolesField := flag.String("access-token-roles-field", "", "Field name within the OIDC access token which contains the roles")
	accessTokenRolesDelimiter := flag.String("access-token-roles-delimiter", "", "which delimiter is being used in the OIDC access token to define multiple roles")

	scope := flag.String("scope", "openid profile email", "Requested scopes")
	logoutPath := flag.String("logout-path", "", "Logout path, if empty, logout not enabled")
	postLogoutPath := flag.String("post-logout-path", "", "Path to redirect to after logout")
	refreshPath := flag.String("refresh-path", "", "Token refresh path, if empty, token refresh not enabled")

	flag.Parse()

	// Setup logger
	log = CreateLogger(*logLevel, *logFormat)

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

	m, err := ttlmap.New()
	if err != nil {
		panic(err)
	}

	wellKnownOpenIDConfiguration, err := wellknownopenidconfiguration.ResolveWellKnownOpenIDConfiguration(log, *oidcIssuer, *clientID, *clientSecret)
	if err != nil {
		log.Fatal("unable to resolve .well-known/openid-configuration: ", err)
	}

	loginURL, err := url.Parse(wellKnownOpenIDConfiguration.AuthorizationEndpoint)
	if err != nil {
		log.Fatal("unable to parse login url: ", err)
	}

	tokenURL, err := url.Parse(wellKnownOpenIDConfiguration.TokenEndpoint)
	if err != nil {
		log.Fatal("unable to parse token url: ", err)
	}
	userURL, err := url.Parse(wellKnownOpenIDConfiguration.UserInfoEndpoint)
	if err != nil {
		log.Fatal("unable to parse user url: ", err)
	}

	// Setup
	fw = &ForwardAuth{
		Path:     fmt.Sprintf("/%s", *path),
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Scope:        *scope,

		LoginURL: loginURL,
		TokenURL: tokenURL,
		UserURL:  userURL,

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieDomains:  cookieDomains,

		Secure: *secure,

		InsecureCertificates: *insecureCertificates,

		Domain:    domain,
		Whitelist: whitelist,

		Prompt:           *prompt,
		UMAAuthorization: *umaAuthorization,

		stateMap:                     m,
		wellKnownOpenIDConfiguration: wellKnownOpenIDConfiguration,
		tokenValidatorEnabled:        *tokenValidatorEnabled,
		PostLogoutPath:               *postLogoutPath,
		LogoutPath:                   *logoutPath,
		RefreshPath:                  *refreshPath,

		AccessTokenRolesField:		  *accessTokenRolesField,
		AccessTokenRolesDelimiter:    *accessTokenRolesDelimiter,
	}

	// Attach handler
	http.HandleFunc("/", handler)

	// Start
	jsonConf, _ := json.Marshal(fw)
	log.Debug("Starting with options: ", string(jsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"
)

// Vars
var fw *ForwardAuth
var log logrus.FieldLogger

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
	// Logging setup
	logger := log.WithFields(logrus.Fields{
		"SourceIP": r.Header.Get("X-Forwarded-For"),
	})
	logger.WithFields(logrus.Fields{
		"Headers": r.Header,
	}).Debugf("Handling request")

	// Parse uri
	uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		logger.Errorf("Error parsing X-Forwarded-Uri, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Handle callback
	if uri.Path == fw.Path {
		logger.Debugf("Passing request to auth callback")
		handleCallback(w, r, uri.Query(), logger)
		return
	}

	isHandled, email := getValidCookieOrHandleRedirect(fw.CookieName, uri.Path, logger, w, r)
	if isHandled == handled(true) {
		// cookie did not validate or there was no cookie, it's already handled
		return
	}

	// Validate user
	emailValid := fw.ValidateEmail(email)
	if !emailValid {
		logger.WithFields(logrus.Fields{
			"email": email,
		}).Errorf("Invalid email")
		http.Error(w, "Not authorized", 401)
		return
	}

	if fw.BearerCookieInUse {
		isHandled, bearerToken := getValidCookieOrHandleRedirect(fw.BearerCookieName, uri.Path, logger, w, r)
		if isHandled == handled(true) {
			// cookie did not validate or there was no cookie, it's already handled
			return
		}
		w.Header().Set("X-Forwarded-Access-Token", base64.StdEncoding.EncodeToString([]byte(bearerToken)))
	}

	// Valid request
	logger.Debugf("Allowing valid request ")
	w.Header().Set("X-Forwarded-User", email)
	w.WriteHeader(200)
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
		}).Warnf("Error validating csrf cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, fw.ClearCSRFCookie(r))

	// Exchange code for token
	token, err := fw.ExchangeCode(r, qs.Get("code"))
	if err != nil {
		logger.Errorf("Code exchange failed with: %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	if fw.UMAAuthorization {
		isAllowedAccess, err := fw.VerifyAccess(token)
		if err != nil {
			logger.Errorf("Access verification failed with: %v", err)
			http.Error(w, "Service unavailable", 503)
			return
		}
		if !isAllowedAccess {
			logger.Infof("Not authorized")
			http.Error(w, "Not authorized", 401)
			return
		}
	}

	// Get user
	user, err := fw.GetUser(token)
	if err != nil {
		logger.Errorf("Error getting user: %s", err)
		return
	}

	// Generate cookie
	http.SetCookie(w, fw.MakeCookie(r, fw.CookieName, user.Email))
	logFields := logrus.Fields{
		"user": user.Email,
	}
	if fw.BearerCookieInUse {
		http.SetCookie(w, fw.MakeCookie(r, fw.BearerCookieName, token))
		logFields["bearer-token-length"] = len(token)
	}
	logger.WithFields(logFields).Infof("Generated auth cookie")

	// Redirect
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

type handled bool

func getValidCookieOrHandleRedirect(cookieName, uriPath string, logger *logrus.Entry, w http.ResponseWriter, r *http.Request) (handled, string) {
	// Get the cookie
	var content string
	c, err := r.Cookie(cookieName)
	if err != nil {
		// Error indicates no cookie, generate nonce
		err, nonce := fw.Nonce()
		if err != nil {
			logger.Errorf("Error generating nonce, %v", err)
			http.Error(w, "Service unavailable", 503)
			return handled(true), content
		}

		// Set the CSRF cookie
		http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
		logger.Debug("Set CSRF cookie and redirecting to oidc login")
		logger.Debug("uri.Path was ", uriPath)
		logger.Debug("fw.Path was ", fw.Path)

		// Forward them on
		http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)
		return handled(true), content
	}

	// Validate cookie
	valid, content, err := fw.ValidateCookie(r, c)
	if !valid {
		logger.Errorf("Invalid cookie: %v", err)
		http.Error(w, "Not authorized", 401)
		return handled(true), content
	}

	return handled(false), content
}

func getOidcConfig(oidc string, insecureCertificates bool) map[string]interface{} {
	uri, err := url.Parse(oidc)
	if err != nil {
		log.Fatalf("failed to parse oidc string: %s", err)
	}
	uri.Path = path.Join(uri.Path, "/.well-known/openid-configuration")

	// allow insecure certificates when enabled
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureCertificates},
		},
	}

	res, err := client.Get(uri.String())
	if err != nil {
		log.Fatalf("failed to get oidc parametere from oidc connect: %s", err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %s", err)
	}
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	log.Debug(result)
	return result
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
	clientId := flag.String("client-id", "", "Client ID (required)")
	clientSecret := flag.String("client-secret", "", "Client Secret (required)")
	bearerCookieName := flag.String("bearer-cookie-name", "_forward_auth_bt", "Bearer Token Cookie Name")
	bearerCookieInUse := flag.Bool("bearer-cookie-enabled", false, "If false, no bearer cookie will be set or validated")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "Deprecated")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	insecureCertificates := flag.Bool("insecure-certificates", false, "Allow insecure certificates")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")
	umaAuthorization := flag.Bool("uma-authorization", false, "whether UMA-based authorization will be performed")
	logLevel := flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error, fatal, panic")
	logFormat := flag.String("log-format", "text", "Log format: text, json, pretty")

	flag.Parse()

	// Setup logger
	log = CreateLogger(*logLevel, *logFormat)

	// Backwards compatibility
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}

	// Check for show stopper errors
	if *clientId == "" || *clientSecret == "" || *secret == "" || *oidcIssuer == "" {
		log.Fatal("client-id, client-secret, secret and oidc-issuer must all be set")
	}

	var oidcParams = getOidcConfig(*oidcIssuer, *insecureCertificates)

	loginURL, err := url.Parse((oidcParams["authorization_endpoint"].(string)))
	if err != nil {
		log.Fatalf("unable to parse login url: %s", err)
	}

	tokenURL, err := url.Parse((oidcParams["token_endpoint"].(string)))
	if err != nil {
		log.Fatalf("unable to parse token url: %s", err)
	}
	userURL, err := url.Parse((oidcParams["userinfo_endpoint"].(string)))
	if err != nil {
		log.Fatalf("unable to parse user url: %s", err)
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

	// Setup
	fw = &ForwardAuth{
		Path:     fmt.Sprintf("/%s", *path),
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "openid profile email",

		LoginURL: loginURL,
		TokenURL: tokenURL,
		UserURL:  userURL,

		BearerCookieName:  *bearerCookieName,
		BearerCookieInUse: *bearerCookieInUse,

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieDomains:  cookieDomains,
		CookieSecure:   *cookieSecure,

		InsecureCertificates: *insecureCertificates,

		Domain:    domain,
		Whitelist: whitelist,

		Prompt:           *prompt,
		UMAAuthorization: *umaAuthorization,
	}

	// Attach handler
	http.HandleFunc("/", handler)

	// Start
	jsonConf, _ := json.Marshal(fw)
	log.Debugf("Starting with options: %s", string(jsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}

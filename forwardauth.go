package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultNonceSize = 16
)

// ForwardAuth represents forward autheentication object
type ForwardAuth struct {
	Path     string
	Lifetime time.Duration
	Secret   []byte

	AuthHost string

	CookieName     string
	CookieDomains  []CookieDomain
	CSRFCookieName string
	InfoCookieName string

	Secure bool

	Domain    []string
	Whitelist []string

	UMAAuthorization bool

	tokenMinValidity        	 time.Duration
	LogoutPath                   string
	PostLogoutPath               string

	AccessTokenRolesField		 string
	AccessTokenRolesDelimiter	 string
}

// Request Validation

// ValidateSessionAuthCookie validates cookies using the following formula: Cookie = hash(secret, cookie domain, content, expires)|expires|content
func (f *ForwardAuth) ValidateSessionAuthCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return false, "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, "", fmt.Errorf("Unable to decode cookie mac: %s", err)
	}

	expectedSignature := f.cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return false, "", fmt.Errorf("Unable to generate mac: %s", err)
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return false, "", fmt.Errorf("Invalid cookie mac %s, expected %s", mac, expected)
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false, "", fmt.Errorf("Unable to parse cookie expiry: %s", err)
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return false, "", errors.New("Cookie has expired")
	}

	// Looks valid
	return true, parts[2], nil
}

// ValidateEmail validates that the email address belongs to one of the white listed
// or configured domains.
func (f *ForwardAuth) ValidateEmail(email string) bool {
	found := false
	if len(f.Whitelist) > 0 {
		for _, whitelist := range f.Whitelist {
			if email == whitelist {
				found = true
			}
		}
	} else if len(f.Domain) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) < 2 {
			return false
		}
		for _, domain := range f.Domain {
			if domain == parts[1] {
				found = true
			}
		}
	} else {
		return true
	}

	return found
}

// Utility methods

// Get the redirect base
func (f *ForwardAuth) redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// Return url
func (f *ForwardAuth) returnURL(r *http.Request) string {
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s%s", f.redirectBase(r), path)
}

// Get oauth redirect uri
func (f *ForwardAuth) redirectURI(r *http.Request) string {
	if use, _ := f.useAuthDomain(r); use {
		proto := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", proto, f.AuthHost, f.Path)
	}

	return fmt.Sprintf("%s%s", f.redirectBase(r), f.Path)
}

// Should we use auth host + what it is
func (f *ForwardAuth) useAuthDomain(r *http.Request) (bool, string) {
	if f.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := f.matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := f.matchCookieDomains(f.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// -- Cookie methods

// ClearCSRFCookie sets a cookie to clear previous CSRF cookie.
func (f *ForwardAuth) ClearCSRFCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     f.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   f.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   f.Secure,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// ClearCookie removes a cookie with given name.
func (f *ForwardAuth) ClearCookie(r *http.Request, name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   f.cookieDomain(r),
		HttpOnly: true,
		Secure:   f.Secure,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// MakeCSRFCookie creates a CSRF cookie (used during login only)
func (f *ForwardAuth) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     f.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   f.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   f.Secure,
		Expires:  f.cookieExpiry(),
	}
}

func (f *ForwardAuth) MakeSessionAuthCookie(r *http.Request, content string) *http.Cookie {
	expires := f.cookieExpiry()
	mac := f.cookieSignature(r, content, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), content)
	return f.MakeCookieWithExpiry(r, f.CookieName, value, expires, true)
}

func (f *ForwardAuth) MakeSessionInfoCookie(r *http.Request, content string) *http.Cookie {
	expires := f.cookieExpiry()
	value := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", expires.Unix(), content)))
	return f.MakeCookieWithExpiry(r, f.InfoCookieName, value, expires, false)
}

// MakeCookieWithExpiry creates a cookie of a given name with given content, with explicit expiry.
func (f *ForwardAuth) MakeCookieWithExpiry(r *http.Request, name, value string, expires time.Time, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   f.cookieDomain(r),
		HttpOnly: httpOnly,
		Secure:   f.Secure,
		Expires:  expires,
	}
}

// ValidateCSRFCookie validates the CSRF cookie against state.
func (f *ForwardAuth) ValidateCSRFCookie(c *http.Cookie, state string) (bool, string, error) {
	if len(c.Value) != 32 {
		return false, "", errors.New("Invalid CSRF cookie value")
	}

	if len(state) < 34 {
		return false, "", errors.New("Invalid CSRF state value")
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", errors.New("CSRF cookie does not match state")
	}

	// Valid, return redirect
	return true, state[33:], nil
}

// Nonce generates a new random nonce using the default nonce size.
func (f *ForwardAuth) Nonce() (string, error) {
	return f.NonceWithSize(defaultNonceSize)
}

// NonceWithSize generates a new random nonce using the specified size.
func (f *ForwardAuth) NonceWithSize(size int) (string, error) {
	// Make nonce
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func (f *ForwardAuth) cookieDomain(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := f.matchCookieDomains(host)
	return domain
}

// Cookie domain
func (f *ForwardAuth) csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := f.useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func (f *ForwardAuth) matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range f.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func (f *ForwardAuth) cookieSignature(r *http.Request, content, expires string) string {
	hash := hmac.New(sha256.New, f.Secret)
	hash.Write([]byte(f.cookieDomain(r)))
	hash.Write([]byte(content))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expirary
func (f *ForwardAuth) cookieExpiry() time.Time {
	return time.Now().Local().Add(f.Lifetime)
}

// -- Cookie Domain

// CookieDomain represents a cookie domain.
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
}

// NewCookieDomain returns a new CookieDomain for a given domain name.
func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match returns true of the given host matches the cookie domain.
func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

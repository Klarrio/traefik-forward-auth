package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// BearerToken is an intermediate object used for parsing bearer tokens
// retrieved from the wire.
type BearerToken struct {
	Jti               string                         `json:"jti"`
	Exp               int64                          `json:"exp"`
	Nbf               int64                          `json:"nbf"`
	Iat               int64                          `json:"iat"`
	Iss               string                         `json:"iss"`
	Aud               string                         `json:"aud"`
	Sub               string                         `json:"sub"`
	Typ               string                         `json:"typ"`
	Azp               string                         `json:"azp"`
	Nonce             string                         `json:"nonce"`
	AuthTime          int64                          `json:"auth_time"`
	SessionState      string                         `json:"session_state"`
	Acr               string                         `json:"acr"`
	RealmAccess       map[string][]string            `json:"realm_access"`
	ResourceAccess    map[string]map[string][]string `json:"resource_access"`
	Scope             string                         `json:"scope"`
	Email             string                         `json:"email"`
	EmailVerified     bool                           `json:"email_verified"`
	Name              string                         `json:"name"`
	PreferredUsername string                         `json:"preferred_username"`
	GivenName         string                         `json:"given_name"`
	FamilyName        string                         `json:"family_name"`
}

// ExpTime returns a time.Time representation of the token exp.
func (bt *BearerToken) ExpTime() time.Time {
	return time.Unix(int64(bt.Exp), 0)
}

func bearerTokenFromWire(wireMessage string) (*BearerToken, error) {

	// we receive a JWT token, the format is:
	// header.payload.signature

	// QUESTION: do we have to validate tokens?
	// We never accept the token from the user.
	// token comes from Keycloak, we store it in memory, serve it to the app.
	// It should be the app's responsibility to validate.

	parts := strings.Split(wireMessage, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token")
	}

	payloadBytes, base64DecodeError := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(parts[1])
	if base64DecodeError != nil {
		return nil, base64DecodeError
	}

	token := &BearerToken{}
	if err := json.Unmarshal([]byte(payloadBytes), token); err != nil {
		return nil, err
	}
	return token, nil
}

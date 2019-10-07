package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// BearerToken is an intermediate object used for parsing bearer tokens
// retrieved from the wire.
type BearerToken struct {
	Exp   float64 `json:"exp"`
	Email string  `json:"email"`
}

// ExpTime returns a time.Time representation of the token exp.
func (bt *BearerToken) ExpTime() time.Time {
	return time.Unix(int64(bt.Exp), 0)
}

func bearerTokenFromWire(wireMessage string) (*BearerToken, error) {

	// we receive a JWT token, the format is:
	// header.payload.signature

	parts := strings.Split(wireMessage, ".") // TODO: token validation
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token")
	}
	payload := parts[1]

	token := &BearerToken{}
	if err := json.Unmarshal([]byte(payload), token); err != nil {
		return nil, err
	}
	return token, nil
}

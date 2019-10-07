package main

import (
	"encoding/json"
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

func bearerTokenFromWire(wireMessage []byte) (*BearerToken, error) {
	token := &BearerToken{}
	if err := json.Unmarshal(wireMessage, token); err != nil {
		return nil, err
	}
	return token, nil
}

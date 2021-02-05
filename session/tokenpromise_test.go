package session

import (
	oidc "github.com/Klarrio/traefik-forward-auth/wellknownopenidconfiguration"
	"testing"
)

func TestTokenPromise(t *testing.T) {
	expectedToken := &oidc.Token{}
	p := NewTokenPromise(func ()(*oidc.Token, error) {
		return expectedToken, nil
	})

	// should properly return the expected result
	tokenResult := <- p.ToChannel()

	if tokenResult.err != nil {
		t.Error("token result shouldn't have an error")
	}
	if tokenResult.token != expectedToken {
		t.Error("token result didn't contain expected token")
	}

	// when already completed, should still return the result for new channels on the same promise
	tokenResult = <- p.ToChannel()
	if tokenResult.token != expectedToken {
		t.Error("didn't return the expected token a second time for a different channel")
	}
}

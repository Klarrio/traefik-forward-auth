package session

import (
	oidc "github.com/Klarrio/traefik-forward-auth/wellknownopenidconfiguration"
	"sync"
)

/**
 * A Promise structure, that promises to provide a token eventually, or an error in case it can't provide it.
 * Can be constructed using the NewTokenPromise(tokenGenerationFunction) function, and you can wait for the token
 * result using the promise.Then(successHandler, errorHandler) function, or by converting the promise to a Go channel with
 * the promise.ToChannel() function.
 */
type TokenPromise struct {
	wg sync.WaitGroup
	token *oidc.Token
	err error
}

type TokenResult struct {
	token *oidc.Token
	err error
}

func NewTokenPromise(tokenGenerationFunction func() (*oidc.Token, error)) *TokenPromise {
	p := &TokenPromise{}
	p.wg.Add(1)
	go func() {
		p.token, p.err = tokenGenerationFunction()
		p.wg.Done()
	}()
	return p
}

/**
 * To handle the result of the promise, which is either the token or an error.
 */
func (p *TokenPromise) Then(successHandler func(token *oidc.Token), errorHandler func(error)) {
	go func() {
		p.wg.Wait()
		if p.err != nil {
			errorHandler(p.err)
			return
		}
		successHandler(p.token)
	}()
}

/**
 * Convert the promise to a Go channel, on which you can then wait for the result.
 * Each invocation of this method returns a new channel, which will deliver the result even if
 * the promise has already completed.
 */
func (p *TokenPromise) ToChannel() chan *TokenResult {
	tokenChannel := make(chan *TokenResult)
	p.Then(
		func (token *oidc.Token) {
			tokenChannel <- &TokenResult{
				token: token,
			}
		},
		func (err error) {
			tokenChannel <- &TokenResult{
				err: err,
			}
		})

	return tokenChannel
}

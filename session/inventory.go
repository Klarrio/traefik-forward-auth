package session

import (
	"fmt"
	"github.com/Klarrio/traefik-forward-auth/ttlmap"
	oidc "github.com/Klarrio/traefik-forward-auth/wellknownopenidconfiguration"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type Inventory struct {
	stateMap                     	ttlmap.TTLMap
	oidcEndpoint 					*oidc.WellKnownOpenIDConfiguration
	tokenValidatorEnabled        	bool
	logger 							logrus.FieldLogger
}

type Metadata struct {
	SessionKey string
	ExpiresAt  time.Time
}

func NewInventory(oidcEndpoint *oidc.WellKnownOpenIDConfiguration, tokenValidatorEnabled bool, logger logrus.FieldLogger) *Inventory {
	stateMap, err := ttlmap.New()
	if err != nil {
		panic(err)
	}

	return &Inventory{ stateMap:  stateMap, oidcEndpoint: oidcEndpoint, tokenValidatorEnabled: tokenValidatorEnabled, logger: logger}
}

func (i *Inventory) StoreSession(sessionKey string, token *oidc.Token, expiry time.Time) {
	i.stateMap.AddWithTTL(sessionKey, token, expiry.Sub(time.Now()))
}

func (i *Inventory) RemoveSession(sessionKey string) {
	i.stateMap.Remove(sessionKey) // cleanup
}

func (i *Inventory) SessionMetadata(sessionKey string) (metadata *Metadata, sessionExists bool) {
	sessionState, sessionExists := i.stateMap.Get(sessionKey)
	if sessionExists {
		sessionMetadata := &Metadata {
			SessionKey: sessionKey,
			ExpiresAt:  sessionState.ExpiresAt(),
		}
		return sessionMetadata, sessionExists
	}

	return nil, sessionExists
}

/**
 * will retrieve the token for the given session if available, or a pending token channel in case the token is being
 * refreshed. Only one of both is being returned. If both are nil, then it means no token exists for the session.
 */
func (i *Inventory) sessionToken(sessionKey string) (availableToken *oidc.Token, pendingToken chan *TokenResult) {
	sessionState, sessionExists := i.stateMap.Get(sessionKey)
	if sessionExists {
		switch val := sessionState.Value().(type) {
		case *oidc.Token:
			return val, nil
		case *TokenPromise:
			return nil, val.ToChannel()
		default:
			return nil, nil
		}
	} else {
		return nil, nil
	}
}

/**
 * Will try to ensure a valid access token. If the token has expired or is about to expire, it will be refreshed. If the
 * token doesn't need to be refreshed, it will be validated (when validation is enabled).
 * When no valid access token can be returned, then the return values will be nil or an empty string.
 */
func (i *Inventory) EnsureValidAccessToken(sessionKey string, tokenMinValidity time.Duration) (accessToken *oidc.BearerToken, rawAccessToken string) {
	sessionMetadata, sessionExists := i.SessionMetadata(sessionKey)
	if !sessionExists {
		i.logger.Error("unable to ensure valid token when no session exists")
		return nil, ""
	}

	tokenRefreshed := false
	var storedToken *oidc.Token
	var bearerToken *oidc.BearerToken
	var err error

	// lock this block of logic, such that only one thread can access it at the same time.
	// This block will determine whether the token needs to be refreshed, and if so, the current thread will take
	// responsibility of doing it. Meanwhile, it will assign a pendingToken to the session, so that all other
	// threads of this session will receive this pending token and will have to wait for the refreshed token.
	// This to avoid that multiple threads/requests try to refresh the same token at the same time, which may result
	// in token refresh failures and unneeded pressure on the oidc server.
	// ---- BEGIN OF LOCK ----
	var mutex = &sync.Mutex{}
	mutex.Lock()
	availableToken, pendingToken := i.sessionToken(sessionKey)

	if availableToken == nil && pendingToken == nil {
		i.logger.Error("no valid token found for session %s", sessionKey)
		return nil, ""
	}

	if availableToken != nil {
		storedToken = availableToken
		bearerToken, err = oidc.BearerTokenFromWire(storedToken.AccessToken)
		if err != nil {
			i.logger.Error("Error parsing stored token, reason ", err)
			return nil, ""
		}

		isAboutToExpire := (bearerToken.Exp - time.Now().Unix()) < (tokenMinValidity.Milliseconds() / 1000) // expires in less then tokenMinValidity
		if isAboutToExpire {
			pendingToken = i.pauseSessionAndRefreshToken(sessionMetadata, storedToken).ToChannel()
		}
	}
	mutex.Unlock()
	// ---- END OF LOCK ----

	if pendingToken != nil {
		i.logger.WithField("sessionKey", sessionMetadata.SessionKey).Debug("waiting for pending token")
		// wait for the token to be refreshed, which we'll receive through the channel
		tokenResult := <-pendingToken
		if tokenResult.err != nil {
			i.logger.Error("failed to acquire refreshed token", tokenResult.err)
			return nil, ""
		}

		storedToken = tokenResult.token
		bearerToken, err = oidc.BearerTokenFromWire(storedToken.AccessToken)
		tokenRefreshed = true
	}

	if storedToken == nil {
		i.logger.WithField("token refreshed", tokenRefreshed).Error("unexpected token unavailability")
		return nil, ""
	}

	// either this thread:
	//   - needed to refresh the token (no token validation required anymore)
	//   - immediately received the available token (token validation might be required)
	//	 - had to wait for the token until it was refreshed (no token validation required anymore)
	if i.tokenValidatorEnabled && !tokenRefreshed {
		if i.validateToken(storedToken) {
			i.logger.WithFields(logrus.Fields{
				"token-validation": true,
				"token refreshed": tokenRefreshed,
			}).Debug("access token valid")
			return bearerToken, storedToken.AccessToken
		} else {
			i.logger.WithFields(logrus.Fields{
				"token-validation": true,
				"token refreshed": tokenRefreshed,
			}).Debug("access token not valid or validity could not be determined")
			return nil, ""
		}
	} else {
		// Valid request
		i.logger.WithFields(logrus.Fields{
			"token-validation": false,
			"token refreshed": tokenRefreshed,
		}).Debug("access token valid")
		return bearerToken, storedToken.AccessToken
	}
}

/**
 * Updates the session state with a promise for a token, while executing the token refresh.
 */
func (i *Inventory) pauseSessionAndRefreshToken(sessionMetadata *Metadata, token *oidc.Token) *TokenPromise {
	tokenPromise := NewTokenPromise(func () (*oidc.Token, error) {
		storedToken, tokenRefreshed := i.refreshToken(sessionMetadata, token)
		if !tokenRefreshed {
			return nil, fmt.Errorf("failed to refresh token for session %s", sessionMetadata.SessionKey)
		} else {
			return storedToken, nil
		}
	})
	exp := sessionMetadata.ExpiresAt.Sub(time.Now())
	i.stateMap.AddWithTTL(sessionMetadata.SessionKey, tokenPromise, exp)

	return tokenPromise
}

func (i *Inventory) refreshToken(sessionMetadata *Metadata, token *oidc.Token) (newToken *oidc.Token, refreshed bool) {
	refreshedToken, refreshError := i.oidcEndpoint.TokenRefresh(token.RefreshToken)
	if refreshError != nil {
		i.logger.WithFields(logrus.Fields{
			"refresh-token-error": refreshError,
		}).Error("error while refreshing token")
		return nil, false
	}

	exp := sessionMetadata.ExpiresAt.Sub(time.Now())
	newTokenEntry := &oidc.Token{
		AccessToken:  refreshedToken.AccessToken,
		TokenType:    refreshedToken.TokenType,
		RefreshToken: refreshedToken.RefreshToken,
		ExpiresIn:    refreshedToken.ExpiresIn,
	}
	i.stateMap.AddWithTTL(sessionMetadata.SessionKey, newTokenEntry, exp)

	i.logger.Infof("Updated session map with refreshed token for session %s", sessionMetadata.SessionKey)

	return newTokenEntry, true
}

func (i *Inventory) validateToken(token *oidc.Token) (valid bool) {
	validationResult, err := i.oidcEndpoint.ValidateToken(token.AccessToken)
	if err != nil {
		i.logger.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to validate token")
		return false
	}

	if validationResult.Active {
		i.logger.WithFields(logrus.Fields{
			"result": validationResult,
		}).Debug("Allowing valid request")
	} else {
		i.logger.WithFields(logrus.Fields{
			"result": validationResult,
		}).Info("Token invalid")
	}

	return validationResult.Active
}

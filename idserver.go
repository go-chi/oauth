package oauth

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

// Generate token response
func (bs *BearerServer) GenerateIdTokenResponse(method string, grantType GrantType, refreshToken string, scope string, code string, redirectURI string, at AuthToken, r *http.Request) (interface{}, int, error) {
	var resp *TokenResponse
	switch grantType {
	case PasswordGrant:
		credential := r.FormValue("name")
		secret := r.FormValue("password")
		groups, err := bs.verifier.ValidateUser(credential, secret, scope, r)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized, err
		}

		token, refresh, idtoken, err := bs.generateIdTokens("RS256", UserToken, credential, scope, groups, at, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError, err
		}

		/* if err = bs.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError, err
		}
		*/

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError, err
		}
	/* case ClientCredentialsGrant:
	if err := bs.verifier.ValidateClient(credential, secret, scope, r); err != nil {
		return "Not authorized", http.StatusUnauthorized, err
	}

	token, refresh, err := bs.generateTokens(ClientToken, credential, scope, r)
	if err != nil {
		return "Token generation failed, check claims", http.StatusInternalServerError, err
	}

	if err = bs.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
		return "Storing Token ID failed", http.StatusInternalServerError, err
	}

	if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
		return "Token generation failed, check security provider", http.StatusInternalServerError, err
	} */
	case AuthCodeGrant:
		parsedJwt, err := ParseJWT(code, &bs.Kc.Pk.PublicKey)
		if err != nil {
			log.Err(err)
		}
		secret = r.FormValue("secret")
		redirect_uri = r.FormValue("redirect_uri")
		nonce := r.FormValue("nonce")
		state := r.FormValue("state")
		client_id := r.FormValue("client_id")

		aud := parsedJwt["aud"].([]interface{})[0].(string)
		at = AuthToken{
			//iss:   client_id,
			//sub:   client_id,
			Aud:   aud,
			Nonce: nonce,
			//exp:       scope,
			Iat: state,
			//auth_time: response_type,
			//acr:       scope,
			//azp:       state,
		}
		if err := bs.verifier.ValidateClient(client_id, secret, scope, r); err != nil {
			return "Not authorized", http.StatusUnauthorized, err
		}
		refresh_token = r.FormValue("refresh_token")
		/* codeVerifier, ok := bs.verifier.(AuthorizationCodeVerifier)
		if !ok {
			return "Not authorized, grant type not supported", http.StatusUnauthorized, nil
		}
		sub, err := ParseJWT(code, bs.Kc)
		user, err := codeVerifier.ValidateCode(sub, credential, secret, code, redirectURI, r)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized, err
		}
		*/
		credential := r.FormValue("name")
		secret := r.FormValue("password")
		groups, err := bs.verifier.ValidateUser(credential, secret, scope, r)
		if err != nil {
			log.Err(err)
		}

		token, refresh, idtoken, err := bs.generateIdTokens("RS256", UserToken, credential, scope, groups, at, r)

		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError, err
		}
		//err = bs.verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError, err
		}

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError, err
		}
	/* case RefreshTokenGrant:
	refresh, err := bs.provider.DecryptRefreshTokens(refreshToken)
	if err != nil {
		return "Not authorized", http.StatusUnauthorized, err
	}

	if _, err = bs.verifier.ValidateTokenID(refresh.TokenType, refresh.Credential, refresh.TokenID, refresh.RefreshTokenID); err != nil {
		return "Not authorized invalid token", http.StatusUnauthorized, err
	}

	token, refresh, err := bs.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope, r)
	if err != nil {
		return "Token generation failed", http.StatusInternalServerError, err
	}

	err = bs.verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
	if err != nil {
		return "Storing Token ID failed", http.StatusInternalServerError, err
	}

	if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
		return "Token generation failed", http.StatusInternalServerError, err
	} */
	default:
		return "Invalid grant_type", http.StatusBadRequest, nil
	}

	return resp, http.StatusOK, nil
}

/* func GenToken(bs *BearerServer, username string, tokenType TokenType, scope string) *Token {
	token := &Token{ID: uuid.Must(uuid.NewV4()).String(), Credential: username, ExpiresIn: bs.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	return token
} */

func refreshToken(tokenId string, username string, tokenType TokenType, scope string) *RefreshToken {
	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: tokenId, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}
	return refreshToken
}

func (bs *BearerServer) generateIdTokens(method string, tokenType TokenType, username, scope string, groups []string, at AuthToken, r *http.Request) (string, *RefreshToken, string, error) {
	//claims := bs.verifier.CreateClaims(username, bs.nonce, groups, at, r)
	claims := CreateClaims(at, bs.nonce, r)

	token, _ := CreateJWT(method, claims, bs.Kc)
	idtoken, _ := CreateJWT(method, claims, bs.Kc)
	refreshToken := refreshToken("token.ID", username, tokenType, scope)

	/* 	if bs.verifier != nil {
		claims, err := bs.verifier.AddClaims("token.TokenType", username, "token.ID", "token.Scope", r)
		if err != nil {
			return nil, nil, "nil", err
		}
		token.Claims = claims
	} */

	return token, refreshToken, idtoken, nil
}

func (bs *BearerServer) cryptIdTokens(token string, refresh *RefreshToken, idToken string, r *http.Request) (*TokenResponse, error) {
	/* cToken, err := bs.provider.CryptToken(token)
	if err != nil {
		return nil, err
	} */
	cRefreshToken, err := bs.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	tokenResponse := &TokenResponse{Token: token, RefreshToken: cRefreshToken, TokenType: BearerToken, ExpiresIn: (int64)(bs.TokenTTL / time.Second), IDtoken: idToken}

	/* if bs.verifier != nil {
		props, err := bs.verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope, r)
		if err != nil {
			return nil, err
		}
		tokenResponse.Properties = props
	} */
	return tokenResponse, err
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

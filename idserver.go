package oauth

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
)

// Generate token response
func (bs *BearerServer) GenerateIdTokenResponse(grantType GrantType, credential string, secret string, refreshToken string, scope string, code string, redirectURI string, r *http.Request) (interface{}, int) {
	var resp *TokenResponse
	switch grantType {
	case PasswordGrant:
		if err := bs.verifier.ValidateUser(credential, secret, scope, r); err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		token, refresh, idtoken, err := bs.generateIdTokens(UserToken, credential, scope, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}

		if err = bs.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case ClientCredentialsGrant:
		if err := bs.verifier.ValidateClient(credential, secret, scope, r); err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		token, refresh, err := bs.generateTokens(ClientToken, credential, scope, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}

		if err = bs.verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case AuthCodeGrant:
		codeVerifier, ok := bs.verifier.(AuthorizationCodeVerifier)
		if !ok {
			return "Not authorized, grant type not supported", http.StatusUnauthorized
		}

		user, err := codeVerifier.ValidateCode(credential, secret, code, redirectURI, r)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		token, refresh, idtoken, err := bs.generateIdTokens(UserToken, credential, scope, r)

		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}
		err = bs.verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case RefreshTokenGrant:
		refresh, err := bs.provider.DecryptRefreshTokens(refreshToken)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		if err = bs.verifier.ValidateTokenID(refresh.TokenType, refresh.Credential, refresh.TokenID, refresh.RefreshTokenID); err != nil {
			return "Not authorized invalid token", http.StatusUnauthorized
		}

		token, refresh, err := bs.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope, r)
		if err != nil {
			return "Token generation failed", http.StatusInternalServerError
		}

		err = bs.verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed", http.StatusInternalServerError
		}
	default:
		return "Invalid grant_type", http.StatusBadRequest
	}

	return resp, http.StatusOK
}

func GenToken(bs *BearerServer, username string, tokenType TokenType, scope string) *Token {
	token := &Token{ID: uuid.Must(uuid.NewV4()).String(), Credential: username, ExpiresIn: bs.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	return token
}

func refreshToken(tokenId string, username string, tokenType TokenType, scope string) *RefreshToken {
	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: tokenId, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}
	return refreshToken
}

func (bs *BearerServer) generateIdTokens(tokenType TokenType, username, scope string, r *http.Request) (*Token, *RefreshToken, string, error) {
	token := GenToken(bs, username, tokenType, scope)
	//token, _ = CreateJWT("RS256", CreateClaims(bs.nonce, , r), bs.pKey, string(bs.Signature))

	idtoken, _ := CreateJWT("RS256", CreateClaims(bs.nonce, r), bs.pKey, string(bs.Signature))
	refreshToken := refreshToken(token.ID, username, tokenType, scope)

	if bs.verifier != nil {
		claims, err := bs.verifier.AddClaims(token.TokenType, username, token.ID, token.Scope, r)
		if err != nil {
			return nil, nil, "nil", err
		}
		token.Claims = claims
	}

	return token, refreshToken, idtoken, nil
}

func (bs *BearerServer) cryptIdTokens(token *Token, refresh *RefreshToken, idToken string, r *http.Request) (*TokenResponse, error) {
	cToken, err := bs.provider.CryptToken(token)
	if err != nil {
		return nil, err
	}
	cRefreshToken, err := bs.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}

	tokenResponse := &TokenResponse{Token: cToken, RefreshToken: cRefreshToken, TokenType: BearerToken, ExpiresIn: (int64)(bs.TokenTTL / time.Second), IDtoken: idToken}

	if bs.verifier != nil {
		props, err := bs.verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope, r)
		if err != nil {
			return nil, err
		}
		tokenResponse.Properties = props
	}
	return tokenResponse, err
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

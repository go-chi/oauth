package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Cookie struct {
	Name       string
	Value      string
	Path       string
	Domain     string
	Expires    time.Time
	RawExpires string

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}

// Generate token response
func (bs *BearerServer) GenerateIdTokenResponse(method string, aud []string, grantType GrantType, refreshToken string, scope string, code string, redirectURI string, at AuthToken, w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	var credential string
	parsedJwt, err := ParseJWT(code, &bs.Kc.Pk["test"].PublicKey)
	if err != nil {
		log.Err(err)
	}
	var sub string
	var client_id string
	if err == nil {
		token := strings.Split(code, ".")[1]
		dIdToken, _ := base64.RawStdEncoding.DecodeString(token)
		jwtParsed := MyCustomClaimss{}
		err = json.Unmarshal(dIdToken, &jwtParsed)
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Println("#####")
		fmt.Println(jwtParsed)
		fmt.Println("#####")
		aud = jwtParsed.Aud
		sub = jwtParsed.Sub
		client_id = jwtParsed.Client_id
		credential = jwtParsed.Sub
	}

	fmt.Println(code)
	var resp *TokenResponse
	switch grantType {
	//--------------------------->to Function and RedirectAccess -->takes that func
	case AuthCodeGrant:
		nonce := parsedJwt["nonce"].(string)
		fmt.Println(nonce)
		at = AuthToken{
			//iss:   client_id,
			Sub:   sub,
			Aud:   aud,
			Nonce: nonce,
			//exp:       scope,
			//Iat: "state",
			//auth_time: response_type,
			//acr:       scope,
			//azp:       state,
		}

		/* if err := bs.verifier.ValidateClient(client_id, "test_secret"); err != nil {
			log.Error().Err(err).Msg("Unable to validate client")
			return "Not authorized", http.StatusOK, nil
		} */

		/*
			user, err := codeVerifier.ValidateCode(sub, credential, secret, code, redirectURI, r)
			if err != nil {
				return "Not authorized", http.StatusUnauthorized, err
			}
		*/

		userStoreName, AuthTarget, err := bs.verifier.GetConnectionTarget(r)
		if err != nil {
			log.Err(err).Msg("Failed getting connection target")
		}
		fmt.Println(AuthTarget)

		groups, err := bs.verifier.ValidateUser(credential, "secret", scope, userStoreName, r)
		if err != nil {
			log.Err(err).Msg("Failed getting groups")
		}

		token, refresh, idtoken, err := bs.generateIdTokens("RS256", aud, UserToken, credential, scope, nonce, groups, at, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError, err
		}

		/* err = bs.verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError, err
		} */

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError, err
		}
	case RefreshTokenGrant:
		refresh, err := bs.provider.DecryptRefreshTokens(refreshToken)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized, err
		}

		/* if _, err = bs.verifier.ValidateTokenID(refresh.TokenType, refresh.Credential, refresh.TokenID, refresh.RefreshTokenID); err != nil {
			return "Not authorized invalid token", http.StatusUnauthorized, err
		} */

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
		}
	default:
		return "Invalid grant_type", http.StatusBadRequest, nil
	}

	return resp, http.StatusOK, nil
}

func refreshToken(tokenId string, username string, tokenType TokenType, scope string) *RefreshToken {
	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: tokenId, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}
	return refreshToken
}

func (bs *BearerServer) generateIdTokens(method string, aud []string, tokenType TokenType, username, scope, nonce string, groups []string, at AuthToken, r *http.Request) (string, *RefreshToken, string, error) {
	claims := bs.verifier.CreateClaims(username, aud, nonce, groups, at, r)

	token, _ := CreateJWT(method, claims, bs.Kc)
	idtoken, _ := CreateJWT(method, claims, bs.Kc)
	refreshToken := refreshToken(aud[0], username, tokenType, scope)

	return token, refreshToken, idtoken, nil
}

func (bs *BearerServer) cryptIdTokens(token string, refresh *RefreshToken, idToken string, r *http.Request) (*TokenResponse, error) {
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
	err := binary.Write(bytesBuffer, binary.BigEndian, x)
	if err != nil {
		log.Err(err)
	}
	return bytesBuffer.Bytes()
}

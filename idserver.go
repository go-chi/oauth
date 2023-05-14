package oauth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
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
func (bs *BearerServer) GenerateIdTokenResponse(codeCheck CodeCheck, method, iss string, aud []string, grantType GrantType, refreshToken string, scope string, code string, redirectURI string, at AuthToken, w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	/* var credential string
	parsedJwt, err := ParseJWT(code, &bs.Kc.Pk["test"].PublicKey)
	if err != nil {
		log.Err(err)
	} */
	//var sub string
	//var client_id string

	//if err == nil {
	/* token := strings.Split(code, ".")[1]
	dIdToken, _ := base64.RawStdEncoding.DecodeString(token)
	jwtParsed := MyCustomClaimss{}
	err = json.Unmarshal(dIdToken, &jwtParsed)
	if err != nil {
		fmt.Println("error:", err)
	} */
	//aud = jwtParsed.Aud
	//sub = jwtParsed.Sub
	//client_id = jwtParsed.Client_id
	//credential = jwtParsed.Sub
	//}

	sub := codeCheck.User
	client_id := codeCheck.ClientId
	aud = append(aud, client_id)
	fmt.Println(code)
	fmt.Println(client_id)
	var resp *TokenResponse
	switch grantType {
	//--------------------------->to Function and RedirectAccess -->takes that func
	case AuthCodeGrant:
		nonce := "nonce"
		fmt.Println(nonce)
		at = AuthToken{
			Iss:   iss,
			Sub:   sub,
			Aud:   aud,
			Nonce: nonce,
			//exp:       scope,
			//Iat: "state",
			//auth_time: response_type,
			//acr:       scope,
			Azp: aud[0],
		}

		/* if err := bs.Verifier.ValidateClient(client_id, "test_secret"); err != nil {
			log.Error().Err(err).Msg("Unable to validate client")
			return "Not authorized", http.StatusOK, nil
		} */

		groups, err := bs.Verifier.ValidateUser(sub, "secret", scope, r)
		if err != nil {
			log.Err(err).Msg("Failed getting groups")
		}

		token, refresh, idtoken, err := bs.generateIdTokens("RS256", aud, UserToken, sub, scope, nonce, groups, at, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError, err
		}

		/* err = bs.Verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
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

		/* if _, err = bs.Verifier.ValidateTokenID(refresh.TokenType, refresh.Credential, refresh.TokenID, refresh.RefreshTokenID); err != nil {
			return "Not authorized invalid token", http.StatusUnauthorized, err
		} */

		token, refresh, err := bs.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope, r)
		if err != nil {
			return "Token generation failed", http.StatusInternalServerError, err
		}

		err = bs.Verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
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
	claims := bs.Verifier.CreateClaims(username, aud, nonce, groups, at, r)

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

	/* if bs.Verifier != nil {
		props, err := bs.Verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope, r)
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

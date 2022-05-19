package oauth

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
)

// Generate token response
func (bs *BearerServer) generateIdTokenResponse(grantType GrantType, credential string, secret string, refreshToken string, scope string, code string, redirectURI string, r *http.Request) (interface{}, int) {
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

		idtoken, err = CreateJWT("RS256", CreateClaims(), bs.pKey)
		fmt.Println("dddd")
		fmt.Println(idtoken)
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

func (bs *BearerServer) generateIdTokens(tokenType TokenType, username, scope string, r *http.Request) (*Token, *RefreshToken, string, error) {
	mySigningKey := []byte("AllYourBase")

	token := &Token{ID: uuid.Must(uuid.NewV4()).String(), Credential: username, ExpiresIn: bs.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	/*
		idclaims, err := bs.verifier.AddIdClaims()
		if err != nil {
			return nil, nil, nil, err
		}
		idtoken := &IDtoken{Claims: idclaims} */

	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"somebody_else"},
		},
	}

	tokens := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	idtoken, _ := tokens.SignedString(mySigningKey)

	if bs.verifier != nil {
		claims, err := bs.verifier.AddClaims(token.TokenType, username, token.ID, token.Scope, r)
		if err != nil {
			return nil, nil, "nil", err
		}
		token.Claims = claims
	}

	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: token.ID, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}

	return token, refreshToken, idtoken, nil
}

func CreateClaims() MyCustomClaims {
	claims := MyCustomClaims{
		"bar",
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"222"},
		},
	}

	return claims

}

func CreateJWT(method string, claims jwt.Claims, privatekey *rsa.PrivateKey) (string, error) {
	switch method {
	case "RS256":
		rt := jwt.GetSigningMethod(method)
		tokens := jwt.NewWithClaims(rt, claims)
		tokens.Header["kid"] = "web"
		signedToken, err := tokens.SignedString(privatekey)
		fmt.Println("###$###")
		fmt.Println(signedToken)
		fmt.Println("--------------")
		//ddd := &privatekey.PublicKey
		jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys", keyfunc.Options{})
		if err != nil {
			log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
		}
		token, err := jwt.Parse(signedToken, jwks.Keyfunc)
		fmt.Println(err)
		fmt.Println(token.Valid)
		if err != nil {
			fmt.Errorf("failed to parse token: %w", err)
		}
		nEnc := base64.URLEncoding.EncodeToString(privatekey.N.Bytes())
		bss := make([]byte, 4)
		binary.LittleEndian.PutUint32(bss, uint32(privatekey.E))
		byteArr := IntToBytes(privatekey.E)
		eEnc := base64.URLEncoding.EncodeToString(byteArr)
		fmt.Println(bss)

		var jwksJSON = json.RawMessage(`{"keys":[{"kid":"web","kty":"RSA","alg":"RS256","use":"sig","n":"` + nEnc + `","e":"` + eEnc + `"}]}`)

		// Create the JWKS from the resource at the given URL.
		jwkss, err := keyfunc.NewJSON(jwksJSON)
		oo := jwkss.ReadOnlyKeys()
		fmt.Println(oo["web"])
		fmt.Println("zzzzzzz")
		//tokenw, err := jwt.Parse(signedToken, jwkss.Keyfunc)
		fmt.Println(signedToken)

		if err != nil {
			log.Fatalf("Failed to create JWKS from JSON.\nError:%s", err.Error())
		}

		/* tt, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
			return ddd, nil
		}) */ /*
			fmt.Println(tt.Valid)
			fmt.Println("token.Signature")
			fmt.Println(tt.Valid) */
		return signedToken, err
	default:
		return "", errors.New("Failed creating jwt")
	}

}
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	client_id := r.FormValue("client_id")
	code := r.FormValue("code")
	client_secret := r.FormValue("client_secret")
	var grant_type GrantType
	grant_type = GrantType(r.FormValue("grant_type"))
	refresh_token := r.FormValue("refresh_token")
	scope := r.FormValue("scope")
	redirect_uri := r.FormValue("redirect_uri")
	fmt.Println("client_id", client_id)
	fmt.Println("code", code)
	fmt.Println("client_secret", client_secret)
	fmt.Println("grant_type", grant_type)
	fmt.Println("refresh_token", refresh_token)
	fmt.Println("scope", scope)
	fmt.Println("redirect_uri", redirect_uri)
	fmt.Println("######")
	resp, _ := bs.generateIdTokenResponse(grant_type, "", "", "", "", "", "", r)
	// generate key

	publickey := bs.pKey.Public()
	fmt.Println(publickey)

	renderJSON(w, resp, 200)
}

type Keys struct {
	Keys []map[string]string `json:"keys"`
}

/* "keys": [
   {
     "alg": "RS256",
     "e": "AQAB",
     "n": "iKqiD4cr7FZKm6f05K4r-GQOvjRqjOeFmOho9V7SAXYwCyJluaGBLVvDWO1XlduPLOrsG_Wgs67SOG5qeLPR8T1zDK4bfJAo1Tvbw
           YeTwVSfd_0mzRq8WaVc_2JtEK7J-4Z0MdVm_dJmcMHVfDziCRohSZthN__WM2NwGnbewWnla0wpEsU3QMZ05_OxvbBdQZaDUsNSx4
           6is29eCdYwhkAfFd_cFRq3DixLEYUsRwmOqwABwwDjBTNvgZOomrtD8BRFWSTlwsbrNZtJMYU33wuLO9ynFkZnY6qRKVHr3YToIrq
           NBXw0RWCheTouQ-snfAB6wcE2WDN3N5z760ejqQ",
     "kid": "U5R8cHbGw445Qbq8zVO1PcCpXL8yG6IcovVa3laCoxM",
     "kty": "RSA",
     "use": "sig"
   }, */
// UserCredentials manages password grant type requests
func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {

	//dd := string(privatekey.D.Bytes())
	sEnc := base64.URLEncoding.EncodeToString(bs.pKey.N.Bytes())
	fmt.Println(sEnc)

	bss := make([]byte, 4)
	binary.LittleEndian.PutUint32(bss, uint32(bs.pKey.E))
	eEnc := base64.URLEncoding.EncodeToString(bss)
	fmt.Println(eEnc)
	//oo := map[string]string{"alg": "PS256"}
	hh := Keys{[]map[string]string{map[string]string{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": "web", "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}

	//{"alg": "PS256", "kid": "1", "n": sEnc, "e": eEnc}}

	renderJSON(w, hh, 200)
}

//client_id:[222] nonce:[N-0.5202118080109033] redirect_uri:[http://localhost:8080/session/callback] response_type:[code] scope:[openid] state:[93c174ac-0d06-46a8-9253-e3b947f40153]
/*
 {
   "access_token": "SlAV32hkKG",
   "token_type": "Bearer",
   "refresh_token": "8xLOxBtZp8",
   "expires_in": 3600,
   "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
     yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
     NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ
     fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz
     AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q
     Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ
     NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd
     QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS
     K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4
     XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
  }
*/

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	id_token := "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJmZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNnspA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcipR2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2macAAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOYu0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl6cQQWNiDpWOl_lxXjQEvQ"
	response_type := r.URL.Query()["response_type"][0]
	fmt.Println(response_type)
	fmt.Println(r.URL.Query())
	//client_id := r.URL.Query()["client_id"][0]
	redirect_uri := r.URL.Query()["redirect_uri"][0]
	redirect_uri = "http://localhost:8081/session/callback?"
	//scope := r.URL.Query()["scope"][0]
	//nonce := r.URL.Query()["nonce"][0]
	state := r.URL.Query()["state"][0]
	access_token := "access_token"
	token_type := "token_type"
	code := "sss"

	switch response_type {
	case "id_token":
		location := redirect_uri + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code":
		code := "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
		location := redirect_uri + "code=" + code + "&state=" + state
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	case "id_token token": //insecure
		location := redirect_uri + "&access_token=" + access_token + "&token_type=" + token_type + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code id_token":
		location := redirect_uri + "&code=" + code + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code token": //insecure
		location := redirect_uri + "&code=" + code + "&access_token=" + access_token + "&token_type=" + token_type + "&state=" + state
		w.Header().Add("Location", location)
		//"code id_token token"
	case "code token id_token": //insecure
		fmt.Println("ssss")
		location := redirect_uri + "&code=" + code + "&access_token=" + access_token + "&token_type=" + token_type + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	default:
		fmt.Println("default")
	}

}

/*
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    error=invalid_request
    &error_description=
      Unsupported%20response_type%20value
    &state=af0ifjsldkj
*/

/* HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
 "access_token": "SlAV32hkKG",
 "token_type": "Bearer",
 "refresh_token": "8xLOxBtZp8",
 "expires_in": 3600,
 "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
   yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
   NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ
   fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz
   AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q
   Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ
   NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd
   QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS
   K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4
   XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
} */

/* HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
 "error": "invalid_request"
}
*/

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
	return tokenResponse, nil
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {

}

func (bs *BearerServer) OpenidConfig(w http.ResponseWriter, r *http.Request) {
	j := OpenidConfig{Issuer: "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io",
		Authorization_endpoint:                "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/authorize",
		Token_endpoint:                        "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/token",
		Userinfo_endpoint:                     "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/userinfo",
		Registration_endpoint:                 "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/clients",
		Jwks_uri:                              "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys",
		Scopes_supported:                      []string{"api", "read_api", "read_user", "read_repository", "write_repository", "read_registry", "write_registry", "sudo", "openid", "profile", "email"},
		Response_types_supported:              []string{"code"},
		Response_modes_supported:              []string{"query", "fragment"},
		Grant_types_supported:                 []string{"authorization_code", "password", "client_credentials", "refresh_token"},
		Token_endpoint_auth_methods_supported: []string{"client_secret_basic", "client_secret_post"},
		Subject_types_supported:               []string{"public"},
		Id_token_signing_alg_values_supported: []string{"RS256"},
		Claims_supported:                      []string{"iss", "sub", "aud", "exp", "iat", "sub_legacy", "name", "nickname", "email", "email_verified", "website", "profile", "picture", "groups", "groups_direct"},
	}
	fmt.Println(j)
	renderJSON(w, j, 200)
}

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signin")
	redirect_uri := "https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/authorize?"
	state := "af0ifjsldkj"
	code := "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
	location := redirect_uri + "code=" + code + "&state=" + state

	http.Redirect(w, r, location, 302)
}

package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/exp/slices"
)

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {
	sEnc := base64.URLEncoding.EncodeToString(bs.pKey.N.Bytes())

	bss := IntToBytes(bs.pKey.E)
	eEnc := base64.URLEncoding.EncodeToString(bss)

	fmt.Println(eEnc)
	hh := Keys{[]map[string]string{{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": bs.Signature, "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}
	renderJSON(w, hh, 200)
}

func GetConfig() {

}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {

	//client_id := r.FormValue("client_id")
	//client_secret := r.FormValue("client_secret")
	code := r.FormValue("code")
	grant_type := GrantType(r.FormValue("grant_type"))
	refresh_token := r.FormValue("refresh_token")
	scope := r.FormValue("scope")
	redirect_uri := r.FormValue("redirect_uri")
	credential := r.FormValue("credential")
	secret := r.FormValue("secret")

	resp, _ := bs.GenerateIdTokenResponse(grant_type, credential, secret, refresh_token, scope, code, redirect_uri, r)

	publickey := bs.pKey.Public()
	fmt.Println(publickey)

	renderJSON(w, resp, 200)

}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenIntrospect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if r.Header["Accept"][0] == "application/json" {
		fmt.Println("#######")
		fmt.Println(r.Header["Accept"])
		fmt.Println(r.Header)
		fmt.Println(r.PostForm["token"])
	}

	if len(r.PostForm["token"]) > 0 {
		we := map[string]bool{
			"active": true,
		}
		s := make(map[string]interface{}, len(we))
		for i, v := range we {
			s[i] = v
		}
		renderJSON(w, s, 200)
	} else {
		renderJSON(w, nil, 400)
	}

}

func CheckAccessToken(act string) {

}

func (bs *BearerServer) OpenidConfig(w http.ResponseWriter, r *http.Request) {
	baseURL := scheme + r.Host
	j := OpenidConfig{
		Issuer:                                baseURL,
		Authorization_endpoint:                baseURL + "/oauth/authorize",
		Token_endpoint:                        baseURL + "/oauth/token",
		Introspection_endpoint:                baseURL + "/oauth/introspect",
		Userinfo_endpoint:                     baseURL + "/oauth/userinfo",
		Registration_endpoint:                 baseURL + "/oauth/clients",
		Jwks_uri:                              baseURL + "/oauth/keys",
		Revocation_endpoint:                   baseURL + "/oauth/revoke",
		Scopes_supported:                      []string{"api", "read_api", "read_user", "read_repository", "write_repository", "read_registry", "write_registry", "sudo", "openid", "profile", "email"},
		Response_types_supported:              []string{"code"},
		Response_modes_supported:              []string{"query", "fragment"},
		Grant_types_supported:                 []string{"authorization_code", "password", "client_credentials", "refresh_token"},
		Token_endpoint_auth_methods_supported: []string{"client_secret_basic", "client_secret_post"},
		Subject_types_supported:               []string{"public"},
		Id_token_signing_alg_values_supported: []string{"RS256"},
		Claims_supported:                      []string{"iss", "sub", "aud", "exp", "iat", "sub_legacy", "name", "nickname", "email", "email_verified", "website", "profile", "picture", "groups", "groups_direct"},
	}
	renderJSON(w, j, 200)
}

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	baseURL := scheme + r.Host
	redirect_uri := baseURL + "/authorize?"
	state := "af0ifjsldkj"
	code := "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
	location := redirect_uri + "code=" + code + "&state=" + state

	http.Redirect(w, r, location, 302)
}
func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	reqURL := r.Header.Get("Referer")
	bs.nonce = r.URL.Query()["nonce"][0]
	response_type := r.URL.Query()["response_type"][0]
	scope := strings.Split(r.URL.Query()["scope"][0], ",")
	redirect_uri := r.URL.Query()["redirect_uri"][0]
	state := r.URL.Query()["state"][0]

	redirect_uri = reqURL + "session/callback?"

	//fmt.Println(redirect_uri)
	//fmt.Println(response_type)
	//fmt.Println(r.URL.Query())
	token_type := "token_type"

	claims := CreateClaims(bs.nonce, r)
	access_token, _ := CreateJWT("RS256", claims, bs.pKey, "324")
	id_token, _ := CreateJWT("RS256", claims, bs.pKey, "324")

	switch response_type {
	case "id_token":
		location := redirect_uri + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code":
		if slices.Contains(scope, "openid") {
			location := redirect_uri + "code=" + access_token + "&state=" + state
			w.Header().Add("Location", location)
			http.Redirect(w, r, location, 302)
		}
	case "id_token token": //insecure
		location := redirect_uri + "&access_token=" + access_token + "&token_type=" + token_type + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code id_token":
		location := redirect_uri + "&code=" + access_token + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code token": //insecure
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + token_type + "&state=" + state
		w.Header().Add("Location", location)
		//"code id_token token"
	case "code token id_token": //insecure
		fmt.Println("ssss")
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + token_type + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	default:
		fmt.Println("default")
	}

}

func UserData() (map[string]interface{}, int, string, error) {
	/* w.WriteHeader(401) // Unauthorized
	w.WriteHeader(403) // Forbidden
	w.WriteHeader(500) // Internal Server Error */

	we := map[string]string{"sub": "dd", "la": "ss"}

	s := make(map[string]interface{}, len(we))
	for i, v := range we {
		s[i] = v
	}

	return s, 200, "application/json", errors.New("")
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {
	/* 	xff := r.Header.Get("X-Forwarded-For")
	 	xfh := r.Header.Get("X-Forwarded-Host")
	 	xfp := r.Header.Get("X-Forwarded-Proto")
		eee := r.Header.Get("Authorization")
	 	words := strings.Fields(eee)
	 	fmt.Println(words[1])
	 	if words[0] == "bearer" && len(words) == 2 {
	 		CheckAccessToken(words[1])
	 	}
	 	hh, err := bs.provider.DecryptToken(words[1])
	 	if err != nil {
	 		fmt.Println(err)
	 	}
	*/
	/* 	Header parameters:
	   	Authorization The access token of type Bearer or DPoP, scoped to retrieve the consented claims for the subject (end-user).
	   	[ DPop ] The DPoP proof JWT, for an access token of type DPoP (optional). Note, the JWT must include an ath claim representing the BASE64URL encoded SHA-256 hash of the DPoP access token value.
	   	[ Issuer ] The issuer URL when issuer aliases are configured, or the issuer URL for a tenant (in the multi-tenant Connect2id server edition). The tenant can be alternatively specified by the Tenant-ID header.
	   	[ Tenant-ID ] The tenant ID (in the multi-tenant Connect2id server edition). The tenant can be alternatively specified by the Issuer header.
	*/
	jsonPayload, rc, contentType, err := UserData()
	if err != nil {

	}
	w.Header().Set("Content-Type", contentType)

	renderJSON(w, jsonPayload, rc)
}

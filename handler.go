package oauth

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
)

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {
	//dd := string(privatekey.D.Bytes())
	sEnc := base64.URLEncoding.EncodeToString(bs.pKey.N.Bytes())

	fmt.Println(sEnc)

	bss := make([]byte, 4)
	binary.LittleEndian.PutUint32(bss, uint32(bs.pKey.E))
	bss = IntToBytes(bs.pKey.E)
	eEnc := base64.URLEncoding.EncodeToString(bss)

	fmt.Println(eEnc)
	//oo := map[string]string{"alg": "PS256"}
	hh := Keys{[]map[string]string{map[string]string{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": "web", "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}

	//{"alg": "PS256", "kid": "1", "n": sEnc, "e": eEnc}}

	renderJSON(w, hh, 200)
}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Form)
	fmt.Println(r.FormValue("nonce"))
	fmt.Println("+++++")
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

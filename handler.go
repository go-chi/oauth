package oauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {
	sEnc := base64.URLEncoding.EncodeToString(bs.pKey.N.Bytes())

	bss := IntToBytes(bs.pKey.E)
	eEnc := base64.URLEncoding.EncodeToString(bss)

	fmt.Println(eEnc)
	hh := Keys{[]map[string]string{{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": "web", "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}
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
func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {

	bs.nonce = r.URL.Query()["nonce"][0]
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

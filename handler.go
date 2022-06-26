package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

func GenJWKS(kc *KeyContainer) {
	sEnc := base64.URLEncoding.EncodeToString(kc.Pk.N.Bytes())
	bss := IntToBytes(kc.Pk.E)
	eEnc := base64.URLEncoding.EncodeToString(bss)
	signature, err := uuid.NewV4()
	if err != nil {

	}
	kc.Keys = Keys{[]map[string]string{{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": signature.String(), "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}

}

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {

	renderJSON(w, bs.Kc.Keys, 200)
}

func GetConfig() {

}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	grant_type := GrantType(r.FormValue("grant_type"))
	//code = r.FormValue("code")
	scope := r.FormValue("scope")
	switch grant_type {
	case "password":
		fmt.Println("testr")
		username := r.FormValue("name")
		credential := r.FormValue("password")
		_, err := bs.verifier.ValidateUser(username, credential, scope, r)
		fmt.Println(err)

	}
	var code string
	if len(r.URL.Query()["client_id"]) > 0 {
		code = r.FormValue("code")
	}

	parsedJwt, err := ParseJWT(code, &bs.Kc.Pk.PublicKey)

	refresh_token := r.FormValue("refresh_token")

	redirect_uri := r.FormValue("redirect_uri")

	secret := r.FormValue("secret")
	//state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	//client_id := r.FormValue("client_id")

	aud := parsedJwt["aud"].([]interface{})[0].(string)
	var at = AuthToken{
		//iss:   client_id,
		//sub:   client_id,
		Aud:   aud,
		Nonce: nonce,
		//exp:       scope,
		//iat:       state,
		//auth_time: response_type,
		//acr:       scope,
		//azp:       state,
	}
	resp, returncode, err := bs.GenerateIdTokenResponse("RS256", grant_type, "credential", secret, refresh_token, scope, code, redirect_uri, at, r)
	if err != nil {
		renderJSON(w, err, 200)
	}
	if returncode != 200 {

	}

	renderJSON(w, resp, 200)

}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenIntrospect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if r.Header["Accept"][0] == "application/json" {
		//fmt.Println(r.PostForm["token"])

		bs.verifier.ValidateJwt(r.PostForm["token"][0])

	} else if r.Header["Accept"][0] == "application/jwt" {

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
	fmt.Fprintf(w, `<h1>Login</h1>
    <form method="post" action="/oauth/auth?%s">
        <label for="name">User name</label>
        <input type="text" id="name" name="name">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Login</button>
    </form>  `, r.URL.RawQuery)
}

func ConvertStructInterface() {

}

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	//Authorization: Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0
	authH := r.Header.Get("Authorization")
	udate, err := bs.verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}

	if len(udate) == 1 {
		switch r.Method {
		case "GET":
			cId := chi.URLParam(r, "id")
			var clientConfig interface{}
			var err error

			clientConfig, err = bs.verifier.StoreClientsGet(cId)

			rc := 200
			if err != nil {
				log.Err(err)
				rc = 400
			}
			renderJSON(w, clientConfig, rc)
		case "POST", "PUT":
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			var jsonMap Registration
			err = json.Unmarshal(body, &jsonMap)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			regResp, err := bs.verifier.StoreClient(jsonMap.Client_name, jsonMap, r.Method)
			renderJSON(w, regResp, 200)
		case "DELETE":
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			var jsonMap Registration
			err = json.Unmarshal(body, &jsonMap)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			err = bs.verifier.StoreClientDelete(jsonMap.Client_name)
			fmt.Println(err)

		default:
			fmt.Println("Too far away.")
		}
	}
}

func validateOidcParams(r *http.Request) bool {
	news := []string{"state", "nonce", "response_type", "scope", "redirect_uri", "client_id"}
	for _, v := range news {
		ok := r.URL.Query().Has(v)
		if ok != true {
			return false
		}
	}
	return true
}

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("Unable to Parse Formdata")
	}
	fmt.Println("+++++")

	var aud, response_type, nonce, redirect_uri, state string
	var scope []string
	if len(r.URL.Query()["client_id"]) > 0 {
		aud = r.URL.Query()["client_id"][0]
		bs.nonce = r.URL.Query()["nonce"][0]
		response_type = r.URL.Query()["response_type"][0]
		scope = strings.Split(r.URL.Query()["scope"][0], ",")
		nonce = r.URL.Query()["nonce"][0]
		redirect_uri = r.URL.Query()["redirect_uri"][0]
		state = r.URL.Query()["state"][0]
	}

	fmt.Println(aud)
	usernameSlice, ok := r.Form["name"]
	passwordSlice, ok := r.Form["password"]

	if !ok || len(usernameSlice) < 1 || len(passwordSlice) < 1 {

	}
	fmt.Println(usernameSlice)
	fmt.Println(passwordSlice)
	username := usernameSlice[0]
	password := passwordSlice[0]
	groups, err := bs.verifier.ValidateUser(username, password, scope[0], r)
	if err != nil {

	}
	fmt.Println(r.URL.Query())
	fmt.Println(groups)

	//fmt.Println(redirect_uri)
	//fmt.Println(response_type)
	//fmt.Println(r.URL.Query())

	var authParameter = AuthToken{
		//iss:   client_id,
		//sub:   client_id,
		Aud:   aud,
		Nonce: nonce,
		//exp:       scope,
		//iat:       state,
		//auth_time: response_type,
		//acr:       scope,
		//azp:       state,
	}

	/* userdata := map[string]string{
		"client_id":     client_id,
		"noce":          nonce,
		"redirect_uri":  redirect_uri,
		"response_type": response_type,
		"state":         state,
		"Subject":       usernameSlice[0],
		"aud":           aud,
	} */

	claims := CreateClaims(authParameter, bs.nonce, r)
	access_token, _ := CreateJWT("RS256", claims, bs.Kc)
	id_token, _ := CreateJWT("RS256", claims, bs.Kc)

	switch response_type {
	case "id_token":
		location := redirect_uri + "?id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code":
		if slices.Contains(scope, "openid") {
			location := redirect_uri + "?code=" + access_token + "&state=" + state
			w.Header().Add("Location", location)
			http.Redirect(w, r, location, 302)
		}
	case "id_token token": //insecure
		location := redirect_uri + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code id_token":
		location := redirect_uri + "&code=" + access_token + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code token": //insecure
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&state=" + state
		w.Header().Add("Location", location)
		//"code id_token token"
	case "code token id_token": //insecure
		fmt.Println("ssss")
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + state
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
	r.ParseForm()
	token := strings.Split(r.Header.Get("Authorization"), " ")

	hh, err := ParseJWT(token[1], &bs.Kc.Pk.PublicKey)
	fmt.Println(hh)
	fmt.Println(err)
	fmt.Println(bs.Kc)
	//Only those claims that are scoped by the token will be made available to the client.
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

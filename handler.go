package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

func getFormData(formValues []string, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	for key, values := range r.Form { // range over map
		for _, value := range values { // range over []string
			fmt.Println(key, value)
		}
	}

}

var refresh_token, redirect_uri, secret, code string
var at AuthToken

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	getFormData([]string{""}, r)
	grant_type := GrantType(r.FormValue("grant_type"))
	//code = r.FormValue("code")
	scope := r.FormValue("scope")

	var code string
	if len(r.URL.Query()["client_id"]) > 0 {
		code = r.FormValue("code")
	}

	resp, returncode, err := bs.GenerateIdTokenResponse("RS256", grant_type, refresh_token, scope, code, redirect_uri, at, r)
	if err != nil {
		renderJSON(w, err, 200)
	}
	if returncode != 200 {
		renderJSON(w, err, 200)
	}
	renderJSON(w, resp, 200)

}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenIntrospect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	token := r.PostForm["token"]
	_, err = bs.verifier.ValidateJwt(token[0])
	if err != nil {
		log.Err(err)
	}
	/* 	if r.Header["Accept"][0] == "application/json" {

	   	} else if r.Header["Accept"][0] == "application/jwt" {

	   	} */

	if len(token) > 0 {
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

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	authH := r.Header.Get("Authorization")
	fmt.Println(authH)
	udate, err := bs.verifier.ExtractJWTtoUserGroup(authH)

	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	fmt.Println(udate)
	fmt.Println("ooo")
	if len(udate) == 1 {
		switch r.Method {
		case "GET":
			cId := chi.URLParam(r, "id")
			var clientConfig interface{}
			var err error
			//u := strings.TrimPrefix(r.URL.Path, "github.com")
			path := r.URL.Path
			base := strings.LastIndex(path, "/")
			fmt.Println(base)
			fmt.Println("**")
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
			err = bs.verifier.StoreClientDelete([]string{jsonMap.Client_name})

		default:
			fmt.Println("Too far away.")
		}
	}
}

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("Unable to Parse Formdata")
	}

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

	usernameSlice, ok := r.Form["name"]
	passwordSlice, ok := r.Form["password"]

	if !ok || len(usernameSlice) < 1 || len(passwordSlice) < 1 {

	}

	username := usernameSlice[0]
	password := passwordSlice[0]
	groups, err := bs.verifier.ValidateUser(username, password, scope[0], r)

	if err != nil {
		fmt.Println(groups)
	}

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
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	token := strings.Split(r.Header.Get("Authorization"), " ")

	hh, err := ParseJWT(token[1], &bs.Kc.Pk.PublicKey)
	fmt.Println(hh)
	fmt.Println(err)
	jsonPayload, rc, contentType, err := UserData()
	if err != nil {
		log.Err(err)
	}
	w.Header().Set("Content-Type", contentType)

	renderJSON(w, jsonPayload, rc)
}

package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

var refresh_token, redirect_uri, Secret, code string
var at AuthToken

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	var at AuthToken
	getFormData([]string{""}, r)
	grant_type := GrantType(r.FormValue("grant_type"))
	scope := r.FormValue("scope")
	aud := r.FormValue("client_id")
	if r.FormValue("code") != "" {
		code = r.FormValue("code")
	}

	resp, returncode, err := bs.GenerateIdTokenResponse("RS256", aud, grant_type, refresh_token, scope, code, redirect_uri, at, w, r)

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
	parsedToken, err := JWTvalid(token[0], &bs.Kc.Pk["test"].PublicKey)
	if err != nil {
		log.Err(err).Msg("Token is invalid")
		renderJSON(w, nil, 401)
		return
	}

	//getting scope
	scopes, err := parseScopes(parsedToken)
	if err != nil {
		log.Err(err).Msg("Parsing scopes failed")
	}
	client_id, err := parseClientid(parsedToken)
	if err != nil {
		log.Err(err).Msg("Parsing client_id failed")
	}
	if client_id == "" {
		log.Err(err).Msg("No Client_id")
		renderJSON(w, nil, 401)
		return
	}

	if unauthorized, _ := Unauthorized(bs, client_id); unauthorized {
		log.Err(err).Msg("Wrong client_id, unauthorized")
		renderJSON(w, nil, 401)
		return
	}

	if unallowed, _ := Forbidden(parsedToken.Claims); unallowed {
		log.Err(err).Msg("Wrong claims, unallowed")
		renderJSON(w, nil, 401)
		return
	}

	if err == nil && len(token) > 0 && parsedToken.Valid {
		qq := IntroSpectReturn{Active: "true", Scope: scopes, Client_id: client_id, Username: "", Token_type: ""}
		renderJSON(w, qq, 200)
		return
	} else if !false {
	} else {
		renderJSON(w, nil, 400)
		return
	}
	//401 Unauthorized
	//403 Forbidden

}

func (bs *BearerServer) TokenRevocation(w http.ResponseWriter, r *http.Request) {
	/* 	400 Bad Request
	Invalid or malformed request.
			   	401 Unauthorized
			   	500 Internal Server Error
				 application/x-www-form-urlencoded
				[ Issuer ]
				Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

				Body
				access_token -- the token is an access token

		refresh_token -- the token is a refresh token
		token=Ohw8choo.wii3ohCh.Eesh1AeDGong3eir
	&token_type_hint=refresh_token
	token=Ohw8choo.wii3ohCh.Eesh1AeDGong3eir
	*/
	if true {
		switch r.Method {
		case "GET":
		default:
			log.Error().Msg("failed")
		}
	}

}

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	authH := r.Header.Get("Authorization")
	groups, err := bs.verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	iamAdmin := slices.Contains(groups, "group1")
	if iamAdmin {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			var err error
			path := r.URL.Path
			base := strings.LastIndex(path, "/")
			clientID := path[base+1:]
			clientConfig, err = bs.verifier.StoreClientGet(clientID)
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST", "PUT":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			var jsonMap Registration
			err = json.Unmarshal(body, &jsonMap)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			regResp, err := bs.verifier.StoreClient(jsonMap.Client_name, jsonMap, r.Method)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			renderJSON(w, regResp, 200)
		case "DELETE":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			var jsonMap Registration
			err = json.Unmarshal(body, &jsonMap)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			err = bs.verifier.StoreClientDelete([]string{jsonMap.Client_name})
			if err != nil {
				renderJSON(w, jsonMap, 500)
			}
			renderJSON(w, jsonMap, 200)
		default:
			log.Error().Msg("failed")
		}
	}
}

func (bs *BearerServer) KeyEndpoint(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	groups, err := bs.verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	iamAdmin := slices.Contains(groups, "group1") */
	if true {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.verifier.StoreKeysGet()
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST":
			fmt.Println("+++++++!+++++++++++")
			var keys map[string]string
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			err = json.Unmarshal(body, &keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			fmt.Println(keys)
			err = bs.verifier.StoreKey(keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":
			path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			//keyDeleteKeyPair(bs.Kc, kid)
			fmt.Println("!!")
			fmt.Println(kid)
			fmt.Println(path)
			bs.verifier.StoreKeyDelete([]string{kid})
		}
	}
}

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err).Msg("Parsing Form failed")
	}
	fmt.Println(r.URL.Query())
	fmt.Println(r.Form)
	fmt.Println(r.Header)
	fmt.Println("####$$$$###")
	formList := []string{"name", "password", "client_id", "response_type", "redirect_uri", "scope", "nonce", "state"}
	//urlValues, err := urlExtractor(r, formList)
	if err != nil {

	}
	if err != nil {
		log.Err(err).Msg("Url Value not present")
	}
	formMap, err := formExtractor(r, formList)
	if err != nil {
		log.Err(err).Msg("Form Value not present")
	}

	_, userstore, err := bs.verifier.GetConnectionTarget(r)
	if err != nil {
		log.Err(err)
	}
	fmt.Println("####§§§§###")

	fmt.Println(formMap)

	_, err = bs.verifier.SessionSave(w, r, formMap["name"][0], "user_session")
	if err != nil {
		log.Err(err)
	}

	groups, err := bs.verifier.ValidateUser(formMap["name"][0], formMap["password"][0], formMap["scope"][0], userstore, r)
	if err != nil {
		fmt.Println(groups)
	}
	fmt.Println("groups")
	fmt.Println(groups)
	groups = []string{"ttest"}
	var authParameter = AuthToken{
		Iss:   formMap["client_id"][0],
		Sub:   formMap["client_id"][0],
		Aud:   formMap["name"][0],
		Nonce: formMap["nonce"][0],
		//exp:       exp,
		//iat:       iat,
		//auth_time: auth_time,
		//acr:       acr,
		//azp:       azp,
	}

	claims := bs.verifier.CreateClaims(formMap["name"][0], formMap["client_id"][0], formMap["nonce"][0], groups, authParameter, r)
	access_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create access_token")
	}
	id_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}
	OpenIDConnectFlows(id_token, access_token, formMap["response_type"][0], formMap["redirect_uri"][0], formMap["state"][0], formMap["scope"], w, r)
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	token := strings.Split(r.Header.Get("Authorization"), " ")

	hh, err := ParseJWT(token[1], &bs.Kc.Pk["test"].PublicKey)
	if err != nil {
		log.Err(err)
	}
	fmt.Println(hh)
	jsonPayload, rc, contentType, err := UserData()
	if err != nil {
		log.Err(err)
	}
	w.Header().Set("Content-Type", contentType)

	renderJSON(w, jsonPayload, rc)
}
func (bs *BearerServer) GetConnectionTarget(r *http.Request) (string, string, error) {
	return "false", "false", nil
}

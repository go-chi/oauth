package oauth

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	bs.Verifier.SessionGet(w, r, "code")
	var at AuthToken
	var code string
	getFormData([]string{""}, r)
	grant_type := GrantType(r.FormValue("grant_type"))
	scope := r.FormValue("scope")
	aud := r.FormValue("client_id")
	if aud == "" {
		log.Error().Msg("Audience not present")
	}

	if r.FormValue("code") != "" {
		code = r.FormValue("code")
	}
	d, ok := bs.Tm.GetValue(code).(CodeCheck)

	fmt.Println("eeeeeee", d, ok)
	resp, returncode, err := bs.GenerateIdTokenResponse("RS256", []string{aud}, grant_type, refresh_token, scope, code, redirect_uri, at, w, r)

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
	renderJSON(w, nil, 200)
}

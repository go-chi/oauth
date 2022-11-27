package oauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	//getting the session
	userID, ok, err := bs.verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Error().Err(err).Msgf("No session present for: %s", userID)
	}
	//getting the form fields
	formList := []string{"client_id", "nonce", "redirect_uri", "response_type", "scope", "state"}
	queryListMap, err := urlExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form value not present")
		renderJSON(w, "Form value is missing", http.StatusForbidden)
		return
	}
	//getting the client data
	aud := queryListMap["client_id"][0]
	client, err := bs.verifier.StoreClientGet(aud)
	if err != nil {
		log.Error().Err(err).Msg("Failed getting client data")
		renderJSON(w, "Client not found", http.StatusForbidden)
		return
	}
	//redirect to error page || Logged in || to login page
	if err != nil || client == nil {
		log.Info().Msgf("Client not found: %s", aud)
		http.Redirect(w, r, "http://ClientNotFound", 401)
	} else if ok && userID != "" {
		RedirectAccess(bs, w, r)
	} else {
		err := bs.verifier.SignInMethod(aud, w, r)
		if err != nil {
			log.Error().Err(err).Msg("Signin method failed")
		}
	}
}

func RedirectAccess(bs *BearerServer, w http.ResponseWriter, r *http.Request) {
	formList := []string{"state", "client_id", "response_type", "redirect_uri", "scope", "nonce"}
	urlValues, err := urlExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form value not present")
		renderJSON(w, "Form value is missing", http.StatusForbidden)
		return
	}

	userID, _, err := bs.verifier.SessionGet(w, r, "user_session")
	if err != nil {
		userID = r.Form.Get("name")
		log.Err(err).Msgf("Unable to get session for User: %s", userID)
	}

	fmt.Println(r.Host)
	fmt.Println("iss")
	clientId := urlValues["client_id"]
	var authParameter = AuthToken{
		Iss:       "iss",
		Sub:       userID,
		Aud:       clientId,
		Exp:       jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Iat:       "",
		Jti:       "",
		Client_id: urlValues["client_id"][0],
		Scope:     []string{"scope1", "scope2"},
		Nonce:     urlValues["nonce"][0],
	}
	_, groups, err := bs.verifier.UserLookup(userID, urlValues["scope"])
	if err != nil {
		log.Err(err).Str("Userlookup", "failed").Msgf("Failed getting Groups from userstore, Group length: %d", len(groups))
	}

	claims := bs.verifier.CreateClaims(userID, urlValues["client_id"], urlValues["nonce"][0], groups, authParameter, r)
	access_token, _ := CreateJWT("RS256", claims, bs.Kc)
	id_token, _ := CreateJWT("RS256", claims, bs.Kc)

	OpenIDConnectFlows(id_token, access_token, urlValues["response_type"][0], urlValues["redirect_uri"][0],
		urlValues["state"][0], urlValues["scopes"], w, r)
}

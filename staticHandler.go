package oauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

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
func (bs *BearerServer) Jwk(w http.ResponseWriter, r *http.Request) {

	renderJSON(w, nil, 200)
}
func RedirectAccess(bs *BearerServer, w http.ResponseWriter, r *http.Request) {
	formList := []string{"state", "client_id", "response_type", "redirect_uri", "scope", "nonce", "scopes"}
	urlValues, err := urlExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form value not present")
	}

	userID, _, err := bs.verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Err(err).Msgf("Unable to get session for User: %s", userID)
		userID = r.Form.Get("name")
	}

	fmt.Println(userID)
	var authParameter = AuthToken{
		Iss:       "iss",
		Sub:       userID,
		Aud:       urlValues["client_id"][0],
		Exp:       jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Iat:       "",
		Jti:       "",
		Client_id: "Testclient_id",
		Scope:     []string{"scope1", "scope2"},
		Nonce:     urlValues["nonce"][0],
	}
	_, groups, err := bs.verifier.UserLookup(userID, urlValues["scopes"])
	if err != nil {
		log.Err(err).Msg("")
	}

	claims := bs.verifier.CreateClaims(userID, urlValues["client_id"][0], urlValues["nonce"][0], groups, authParameter, r)
	access_token, _ := CreateJWT("RS256", claims, bs.Kc)
	id_token, _ := CreateJWT("RS256", claims, bs.Kc)

	OpenIDConnectFlows(id_token, access_token, urlValues["response_type"][0], urlValues["redirect_uri"][0],
		urlValues["state"][0], urlValues["scopes"], w, r)
}

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	userID, ok, err := bs.verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Error().Err(err).Msgf("No session present for: %s", userID)
	}
	formList := []string{"client_id", "nonce", "redirect_uri", "response_type", "scope", "state"}
	queryListMap, err := urlExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msgf("Form value not present %s", userID)
		return
	}
	aud := queryListMap["client_id"][0]
	client, err := bs.verifier.StoreClientGet(aud)
	if err != nil {
		log.Error().Err(err).Msg("Failed getting client data")
	}
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

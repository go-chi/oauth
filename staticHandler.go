package oauth

import (
	"fmt"
	"net/http"

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

func SaveCookie(w http.ResponseWriter, r *http.Request) (bool, error) {
	cookies, err := r.Cookie("goID")
	if err == nil && cookies.Value == "testing" {
		fmt.Println(cookies)
	}
	return true, nil
}
func (bs *BearerServer) SaveCookie(w http.ResponseWriter, r *http.Request) (bool, error) {

	return true, nil
}

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	cookieCheck, _ := SaveCookie(w, r)
	if cookieCheck {
		state := r.URL.Query()["state"][0]
		access_token, err := JWTCreateAccessT(bs, r)
		if err != nil {
			log.Err(err)
		}

		location := redirect_uri + "?code=" + access_token + "&state=" + state
		fmt.Println(location)
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	}
	fmt.Fprintf(w, `<h1>Login</h1>
    <form method="post" action="/oauth/auth?%s">
        <label for="name">User name</label>
        <input type="text" id="name" name="name">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Login</button>
    </form>  `, r.URL.RawQuery)
}

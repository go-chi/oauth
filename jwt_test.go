package oauth

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func TestGenKid(t *testing.T) {
	kid, err := GenKid()
	if kid == "" && err != nil {
		t.Error()
	}
}

func TestCreateJWT(t *testing.T) {
	clientConfig := ClientConfig{Method: "RS256", Claims: nil, Kid: sig.String()}
	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu46.gitpod.io"+"/oauth/keys", keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}
	signedToken, err := CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
	token, err := jwt.Parse(signedToken, jwks.Keyfunc)
	if err != nil {
		t.Error(err)
	}
	if token.Valid {
		t.Error(token.Valid)
	}
}

func TestJwtValidate(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	var authParameter = AuthToken{
		//iss:   client_id,
		//sub:   client_id,
		Aud:   "aud",
		Nonce: "nonce",
		//exp:       scope,
		//iat:       state,
		//auth_time: response_type,
		//acr:       scope,
		//azp:       state,
	}

	jw, err := CreateJWT("RS256", CreateClaims(authParameter, bs.nonce, req), bs.Kc)
	if err != nil {
		fmt.Println(err)
	}

	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu46.gitpod.io/"+"/oauth/keys", keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}

	token, err := jwt.Parse(jw, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}
	if token == nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}

}

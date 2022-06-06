package oauth

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func re(pKey *rsa.PrivateKey) (interface{}, error) {

	return pKey.PublicKey, nil
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
	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
	)

	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}

	jw, err := CreateJWT("RS256", CreateClaims(bs.nonce, req), bs.Kc)
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

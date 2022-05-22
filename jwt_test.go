package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func re(pKey *rsa.PrivateKey) (interface{}, error) {

	return pKey.PublicKey, nil
}

func TestCreateJWT(t *testing.T) {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientConfig := ClientConfig{Method: "RS256", Claims: nil, Kid: ""}
	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys", keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}
	signedToken, err := CreateJWT(clientConfig.Method, clientConfig.Claims, privatekey, clientConfig.Kid)
	token, err := jwt.Parse(signedToken, jwks.Keyfunc)
	if err != nil {
		t.Error(err)
	}
	if token.Valid {
		t.Error(token.Valid)
	}
}

func TestJwtValidate(t *testing.T) {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)

	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
		privatekey)

	jw, err := CreateJWT("RS256", CreateClaims(bs.nonce), bs.pKey, "")
	if err != nil {
		fmt.Println(err)
	}

	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys", keyfunc.Options{})
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

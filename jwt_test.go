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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	sss "github.com/lestrrat-go/jwx/v2/jwt"
)

func re(pKey *rsa.PrivateKey) (interface{}, error) {

	return pKey.PublicKey, nil
}

func TestCreateJWT(t *testing.T) {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientConfig := ClientConfig{Method: "", Claims: nil, Privatekey: privatekey, Kid: ""}
	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys", keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}
	signedToken, err := CreateJWT(clientConfig.Method, clientConfig.Claims, clientConfig.Privatekey, clientConfig.Kid)
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
	pubkey, err := jwk.PublicKeyOf(privatekey)
	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
		privatekey)

	jw, err := CreateJWT("RS256", CreateClaims(bs.nonce), bs.pKey, "")
	//fmt.Println(jw)
	if err != nil {
		fmt.Println(err)
	}

	jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu45.gitpod.io/keys", keyfunc.Options{})
	verifiedToken, err := sss.Parse([]byte(jw), sss.WithKey(jwa.RS256, pubkey))
	fmt.Println(verifiedToken)
	fmt.Println(err)
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}

	if err != nil {
		log.Fatalf("Failed to create JWKS from JSON.\nError:%s", err.Error())
	}
	token, err := jwt.Parse(jw, jwks.Keyfunc)
	fmt.Println("token")
	fmt.Println(token)
	fmt.Println("token")
	fmt.Println(err)

	t.Error()
}

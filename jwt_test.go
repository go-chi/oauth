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

func TestJwtValidate(t *testing.T) {

	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubkey, err := jwk.PublicKeyOf(privatekey)
	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
		privatekey)

	jw, err := CreateJWT("RS256", CreateClaims(), bs.pKey)
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
	//var jwksJSON = json.RawMessage(`{"keys":[{"kid":"web","kty":"RSA","alg":"RS256","use":"sig","e":"AQABAA","n":"1txvd1RQWVXJL8DDbz3DkAkjWBnRo2/zUYkUukvvxnc9R7OPiMXAiOvq9fUXGmUWj6f8mkuVLTiVjPC4Pqc14PB2Qt8hZ/dfxCnLUgrzf99CPq5tZNMhEwzSP/LqeXz+JIOG3TnBDekX0HcYx+a2v6eDXGoZGzHMnbzmHfRMYrxj49z3Ggr7ySPh5vzXalZemvJeAX294gNA+QjLaSps41DhBr+TeLSczIQA25BpVD1l+Xxj+DU+T0uuFo6ucS+rKTLCmEk/Z8dJJiU1x8XFmTEPCe8dhh2hAC0MyXO1Lf75X1C7O8uxmBt6BWh36RROVWkGXR9K1rhgTL98IB/SVQ"}]}`)
	//{"keys":[{"kid":"web","kty":"RSA","alg":"PS256","use":"sig","e":"NjU1Mzc=","n":"uhQt0oZtTSKPt2/JPqCH+NfOQE6cR9vdjdL2cNhS9kvDiHib55ILtxT5Wnti/yBBdb+d4FH+yzIHiLT/91gj3oVJoFwKWFk1W5bK2Ok7U+gz44fdRpQXCUNL2i4MQRzest4/RSQW8slgvuOGfW9BiXkMrf5ci7WYyuW+eTB2RZzY5P2OEPjTJydo1bxI7gSzShsblxXBol2Mi4v1WFJjt5YPOZ9CMu6Wju0LTW3N7X7+kzE+zFUQW8/7zczeWhM4GQOW5So4S7jdh0PMpCV0eqB1pyW7Xv88ueKneQvU3NDmNsZpXu6ZpTZ2i3GFHwttEwFcrK+zsnHY6T89GC+hmQ=="}]}
	// Create the JWKS from the resource at the given URL.
	//jwks, err = keyfunc.NewJSON(jwksJSON)
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

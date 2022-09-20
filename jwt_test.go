package oauth

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
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
	assertCorrectMessage := func(t testing.TB, got ClientConfig, want map[string]interface{}) {
		t.Helper()

		signedToken, err := CreateJWT(got.Method, got.Claims, bs.Kc)
		if err != nil {
			t.Error(err)
		}
		//token, err := jwt.Parse(signedToken, jwks.Keyfunc)
		pub := &bs.Kc.Pk.PublicKey
		token, err := jwt.Parse(signedToken, func(t *jwt.Token) (interface{}, error) { return pub, nil })
		if err != nil {
			t.Error(err)
		}
		if !token.Valid {
			t.Error(token.Valid)
		}

	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := ClientConfig{Method: "RS256", Claims: testclaims, Kid: sig.String()}
		want := map[string]interface{}{"name": "tester"}
		assertCorrectMessage(t, got, want)
	})
	t.Run("Registration Test 1", func(t *testing.T) {
		got := ClientConfig{Method: "RS256", Claims: testclaims, Kid: sig.String()}
		want := map[string]interface{}{"name": "tester"}
		assertCorrectMessage(t, got, want)
	})

}

func TestJwtValidate(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}

	jw, err := CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
	if err != nil {
		fmt.Println(err)
	}
	httpRecorder := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.ReturnKeys)
	handler.ServeHTTP(httpRecorder, req)
	//jwks, err := keyfunc.Get("https://8080-christhirst-oauth-k190qu9sfa8.ws-eu46.gitpod.io/"+"/oauth/keys", keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}

	bodybytes := httpRecorder.Body
	jwks, err := keyfunc.NewJSON(bodybytes.Bytes())
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

	if !token.Valid {
		t.Error()
	}
}

func TestJwtGroup(t *testing.T) {
	jw, err := CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
	if err != nil {
		log.Fatalf("Failed to create JWT - Error:%s", err.Error())
	}

	groups, err := ExtractJWTtoUserGroup(jw, &bs.Kc.Pk.PublicKey)
	if err != nil {
		log.Fatalf("Failed to get groups - Error:%s", err.Error())
	}

	for _, v := range groups {
		fmt.Println(v)
	}
	if len(groups) < 1 {
		t.Error()
	}
}

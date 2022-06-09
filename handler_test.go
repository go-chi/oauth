package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
)

var pk, _ = rsa.GenerateKey(rand.Reader, 2048)
var sig, _ = uuid.FromBytes(pk.PublicKey.N.Bytes())

var bs = NewBearerServer(
	"mySecretKey-10101",
	time.Second*120,
	&TestUserVerifier{},
	nil,
)

type postData struct {
	key   string
	value string
}

func TestGenJWKS(t *testing.T) {}

func TestReturnKeys(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.ReturnKeys)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa Keys
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}

	for _, v := range tsa.Keys {
		for ii, _ := range v {
			if (ii != "alg") && (ii != "e") && (ii != "n") && (ii != "kid") && (ii != "kty") && (ii != "use") {
				t.Error(err)
				t.Errorf("expected other key: %s but got: ", ii)
			}

		}
	}

}

func TestGetConfig(t *testing.T) {}

func TestTokenEndpoint(t *testing.T) {}
func TestTokenIntrospect(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("POST", "/oauth/introspect", nil)
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.TokenIntrospect)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa Keys
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}

	for _, v := range tsa.Keys {
		for ii, _ := range v {
			if (ii != "alg") && (ii != "e") && (ii != "n") && (ii != "kid") && (ii != "kty") && (ii != "use") {
				t.Error(err)
				t.Errorf("expected other key: %s but got: ", ii)
			}

		}
	}

}
func TestOpenidConfig(t *testing.T) {}

func TestSignIn(t *testing.T) {}

func TestRegistration(t *testing.T) {

	got := Registration{
		Application_type: "web",
		Redirect_uris: []string{
			"https://client.example.org/callback",
			"https://client.example.org/callback2",
		},
		Client_name:                "My Cool App",
		Logo_uri:                   "https://client.example.org/logo.png",
		Token_endpoint_auth_method: "client_secret_basic",
		Contacts:                   []string{"admin@example.org"},
	}

	empJSON, err := json.Marshal(got)
	if err != nil {
		log.Fatalf(err.Error())
	}
	fmt.Printf("Marshal funnction output %s\n", string(empJSON))

	//pass request to handler with nil as parameter
	req, err := http.NewRequest("POST", "/oauth/clients", bytes.NewBuffer(empJSON))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.Registration)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)
	fmt.Println(rr.Body)
	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa map[string]interface{}
	err = decoder.Decode(&tsa)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(tsa)
	t.Error()
	/*
		{
			"application_type"                : "web",
			"redirect_uris"                   : [ "https://client.example.org/callback",
												  "https://client.example.org/callback2" ],
			"client_name"                     : "My Cool App",
			"logo_uri"                        : "https://client.example.org/logo.png",
			"token_endpoint_auth_method"      : "client_secret_basic",
			"contacts"                        : [ "admin@example.org" ]
		  }
	*/

	/* assertCorrectMessage := func(t testing.TB, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}

	t.Run("saying hello to people", func(t *testing.T) {
		got := "Hello()"
		want := "Hello, Chris"
		assertCorrectMessage(t, got, want)
	})

	t.Run("say 'Hello, World' when an empty string is supplied", func(t *testing.T) {
		got := "Hello()"
		want := "Hello, World"

		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}) */
}

func TestValidateOidcParams(t *testing.T) {}

func TestGetRedirect(t *testing.T) {}

func TestUserData(t *testing.T) {
	groups := []string{"Admin", "User"}

	s := make([]interface{}, len(groups))
	for i, v := range groups {
		s[i] = v
	}
}

func TestUserInfo(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.UserInfo)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa map[string]interface{}
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}
	fmt.Println(tsa)
	t.Error()

}

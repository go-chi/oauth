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

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
)

var theTests = []struct {
	name               string
	url                string
	method             string
	params             []postData
	expectedStatusCode int
	Host               string
	Authorization      string
}{
	{"config", "/oauth/clients/s6BhdRkqt3", "GET",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
	{"config", "/oauth/clients", "GET",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
}

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

func TestRegistrationGet(t *testing.T) {
	mux := chi.NewRouter()
	mux.Get("/oauth/clients/{id}", bs.Registration)
	mux.Get("/oauth/clients", bs.Registration)
	ts := httptest.NewTLSServer(mux)

	for _, e := range theTests {
		if e.method == "GET" {
			fmt.Println(ts.URL)
			resp, err := ts.Client().Get(ts.URL + e.url)
			fmt.Println(e.url)
			fmt.Println(resp.Header)
			fmt.Println(resp.StatusCode)
			if err != nil {
				t.Log(err)
			}
			if resp.StatusCode != e.expectedStatusCode {
				t.Errorf("for %s, expected %d but got %d", e.name, e.expectedStatusCode, resp.StatusCode)
			}
		}

	}
	defer ts.Close()
}

func TestRegistrationPost(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get Registration, want string) {
		t.Helper()

		wants := []string{"client_id", "registration_access_token",
			 "client_name", "logo_uri", "contacts", "application_type", "grant_types", "response_types",
			"redirect_uris", "token_endpoint_auth_method", "id_token_signed_response_alg", "subject_type"}

		empJSON, err := json.Marshal(get)
		if err != nil {
			log.Fatalf(err.Error())
		}
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
		bodybytes := rr.Body
		jmap, err := StructToJson(bodybytes)
		//bodyBytes, err := io.ReadAll(rr.Body)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range wants {
			_, ok := jmap[v]
			if !ok {
				t.Errorf("%q does not exist", v)
			}
		}
		/*
			if got != want {
				t.Errorf("got %q want %q", got, want)
			} */
	}

	t.Run("Registration Test 1", func(t *testing.T) {
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
		want := "got"
		assertCorrectMessage(t, got, want)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
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
		want := "Hello, World"
		assertCorrectMessage(t, got, want)

	})

	/* 	// Check the status code is what we expect.
	   	if status := rr.Code; status != http.StatusOK {
	   		t.Errorf("handler returned wrong status code: got %v want %v",
	   			status, http.StatusOK)
	   	} */
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

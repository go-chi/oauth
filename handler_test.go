package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	gohelper "github.com/christhirst/gohelper/json"
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
	{"config1", "/oauth/clients/s6BhdRkqt3", "GET",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
	{"config2", "/oauth/clients", "GET",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
	{"config3", "/oauth/clients", "POST",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
}

var client = Registration{
	Client_id:      "client1",
	Redirect_uris:  []string{"http://test.de"},
	Response_types: "POST",
}

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

func TestGetConfig(t *testing.T) {}

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

//req.Header.Add("Bearer","eee")
func TestRegistrationGet(t *testing.T) {
	mux := chi.NewRouter()
	mux.Get("/oauth/clients/{id}", bs.Registration)
	//mux.Get("/oauth/clients", bs.Registration)
	mux.Post("/oauth/clients", bs.Registration)
	mux.Get("/oauth/clients", bs.Registration)

	ts := httptest.NewTLSServer(mux)

	for _, e := range theTests {
		if e.method == "GET" && e.name == "config12" {

			fmt.Println(ts.URL)
			resp, err := ts.Client().Get(ts.URL + e.url)
			if err != nil {
				t.Log(err)
			}
			if resp.StatusCode != e.expectedStatusCode {
				t.Errorf("for %s, expected %d but got %d", e.name, e.expectedStatusCode, resp.StatusCode)
			}
		} else if e.method == "POST3" {
			var buf bytes.Buffer
			err := json.NewEncoder(&buf).Encode(client)
			fmt.Println(err, buf)
			resp, err := ts.Client().Post(ts.URL+"/oauth/clients", "application/json", &buf)

			fmt.Println(resp)
		} else if e.name == "config2" {
			fmt.Println(ts.URL + e.url)
			resp, err := ts.Client().Get(ts.URL + e.url)

			if err != nil {
				t.Log(err)
			}
			if resp.StatusCode != e.expectedStatusCode {
				t.Errorf("for %s, expected %d but got %d", e.name, e.expectedStatusCode, resp.StatusCode)
			}
		}
		t.Error()
	}
	defer ts.Close()
}

func TestRegistrationPost(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get Registration, want Registration) {
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
		jmap, err := gohelper.StructToJson(bodybytes)
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
		jsonStr, err := json.Marshal(jmap)
		fmt.Println(string(jsonStr))

		// convert json to struct
		s := Registration{}
		json.Unmarshal(jsonStr, &s)

		if get.Client_id != want.Client_id {
			t.Errorf("got %q want %q", get, want)
		}
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
		want := Registration{
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
		want := Registration{
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
		assertCorrectMessage(t, got, want)

	})

	/* 	// Check the status code is what we expect.
	   	if status := rr.Code; status != http.StatusOK {
	   		t.Errorf("handler returned wrong status code: got %v want %v",
	   			status, http.StatusOK)
	   	} */
}

func TestRegistrationGets(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get Registration, want Registration) {
		t.Helper()
		wants := []string{"client_id", "registration_access_token",
			"client_name", "logo_uri", "contacts", "application_type", "grant_types", "response_types",
			"redirect_uris", "token_endpoint_auth_method", "id_token_signed_response_alg", "subject_type"}

		empJSON, err := json.Marshal(get)
		if err != nil {
			log.Fatalf(err.Error())
		}
		//pass request to handler with nil as parameter
		req, err := http.NewRequest("GET", "/oauth/clients", bytes.NewBuffer(empJSON))
		req.Header.Set("Authorization", "Bearer ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6")
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.Registration)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)
		bodybytes := rr.Body
		jmap, err := gohelper.StructToJson(bodybytes)
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
		jsonStr, err := json.Marshal(jmap)
		fmt.Println(string(jsonStr))

		// convert json to struct
		s := Registration{}
		json.Unmarshal(jsonStr, &s)

		if get.Client_id != want.Client_id {
			t.Errorf("got %q want %q", get, want)
		}
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
		want := Registration{
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
		want := Registration{
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
		assertCorrectMessage(t, got, want)

	})

	/* 	// Check the status code is what we expect.
	   	if status := rr.Code; status != http.StatusOK {
	   		t.Errorf("handler returned wrong status code: got %v want %v",
	   			status, http.StatusOK)
	   	} */
}

func TestValidateOidcParams(t *testing.T) {}

func TestGetRedirect(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, got, want map[string]interface{}) {
		t.Helper()

		form := url.Values{}

		form.Add("name", "tester")
		form.Add("password", "testpw")
		req, err := http.NewRequest("POST", "/oauth/auth", nil)
		req.PostForm = form
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.GetRedirect)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)
		bodybytes := rr.Body
		jmap, err := gohelper.StructToJson(bodybytes)
		//bodyBytes, err := io.ReadAll(rr.Body)
		if err != nil {
			log.Fatal(err)
		}

		jsonStr, err := json.Marshal(jmap)
		fmt.Println(string(jsonStr))

		// convert json to struct
		s := Registration{}
		json.Unmarshal(jsonStr, &s)

	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := map[string]interface{}{"name": "tester"}
		want := map[string]interface{}{"name": "tester"}
		assertCorrectMessage(t, got, want)
	})

}

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

package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/christhirst/gohelper/ijson"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
)

var pk, _ = rsa.GenerateKey(rand.Reader, 4096)
var bs = NewBearerServer(
	"mySecretKey-10101",
	time.Second*120,
	&TestUserVerifier{},
	nil,
)
var testclaims = MyCustomClaims{
	Foo:    "cn",
	Nonce:  "nonce",
	Groups: []string{"testgroup1", "testgroup2"},
	RegisteredClaims: jwt.RegisteredClaims{
		// A usual scenario is to set the expiration time relative to the current time
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "baseURL" + "",
		Subject:   "testSubject",
		ID:        "1",
		Audience:  []string{"rrr"},
	},
}

var clientConfig = ClientConfig{Method: "RS256", Claims: testclaims, Kid: sig.String()}
var signedToken, _ = CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
var theTests = []struct {
	name               string
	url                string
	method             string
	params             []postData
	expectedStatusCode int
	Host               string
	Authorization      string
}{
	{
		"config1", "/oauth/clients", "POST",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config2", "/oauth/clients/testclient1", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config3", "/oauth/clients", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config4", "/oauth/clients/testclient1", "DELETE",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config5", "/oauth/clients/testclient1", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
}

var client = Registration{
	Client_id:      "testclient1",
	Client_secret:  "test_secret",
	Redirect_uris:  []string{"http://test.de"},
	Response_types: "POST",
}

var sig, _ = uuid.FromBytes(pk.PublicKey.N.Bytes())

func assertResponseBody[k comparable](t testing.TB, got, want k) {
	t.Helper()
	if got != want {
		t.Errorf("expected %v but got %v", got, want)
	}
}

/*
	 func executeRequest(req *http.Request, mux *chi.Mux) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
*/
func createRequest[K any](c K, t *testing.T) bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(c)
	if err != nil {
		t.Errorf("json encoding failed %v", err)
	}
	return buf
}

func TestRegistrationGet(t *testing.T) {
	mux := chi.NewRouter()
	mux.HandleFunc("/oauth/clients/{id}", bs.Registration)
	mux.HandleFunc("/oauth/clients", bs.Registration)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, e := range theTests {
		if e.method == "GET" {
			resp, err := ts.Client().Get(ts.URL + e.url)
			jsonMap := &Registration{}
			ParseBody(resp.Body, jsonMap)
			if err != nil {
				t.Log(err)
			}
			assertResponseBody(t, resp.StatusCode, e.expectedStatusCode)
		} else if e.method == "POST" {
			buf := createRequest(client, t)
			resp, err := ts.Client().Post(ts.URL+"/oauth/clients", "application/json", &buf)
			if err != nil {
				t.Errorf("json encoding failed %v", err)
			}
			assertResponseBody(t, resp.StatusCode, e.expectedStatusCode)
		} else if e.method == "DELETE" {
			req, err := http.NewRequest("DELETE", ts.URL+"/oauth/clients/"+client.Client_id, nil)
			if err != nil {
				t.Errorf("json encoding failed %v", err)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Errorf("json encoding failed %v", err)
			}
			assertResponseBody(t, resp.StatusCode, e.expectedStatusCode)
		}
	}
	t.Error()
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
		httpRecorder := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.Registration)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(httpRecorder, req)
		bodybytes := httpRecorder.Body
		jmap, err := ijson.StructToJson(bodybytes)
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
		if err != nil {
			log.Fatal(err)
		}

		// convert json to struct
		s := Registration{}
		err = json.Unmarshal(jsonStr, &s)
		if err != nil {
			log.Fatal(err)
		}
		if get.Client_id != want.Client_id {
			t.Errorf("got %q want %q", get, want)
		}
	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := Registration{
			Client_id:     "testClientID",
			Client_secret: "testClientSecret",
			Redirect_uris: []string{
				"https://client.example.org/callback",
				"https://client.example.org/callback2",
			},
			Grant_types:                  "openid",
			Response_types:               "openid",
			Id_token_signed_response_alg: "rs256",
			Subject_type:                 "test",
			Application_type:             "web",
			Client_name:                  "MyCoolApp",
			Logo_uri:                     "https://client.example.org/logo.png",
			Token_endpoint_auth_method:   "client_secret_basic",
			Contacts:                     []string{"admin@example.org"},
			Registration_access_token:    "testRegToken",
		}

		assertCorrectMessage(t, got, got)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
		got := Registration{
			Client_id:     "testClientID",
			Client_secret: "testClientSecret",
			Redirect_uris: []string{
				"https://client.example.org/callback",
				"https://client.example.org/callback2",
			},
			Grant_types:                  "openid",
			Response_types:               "openid",
			Id_token_signed_response_alg: "rs256",
			Subject_type:                 "test",
			Application_type:             "web",
			Client_name:                  "MyCoolApp",
			Logo_uri:                     "https://client.example.org/logo.png",
			Token_endpoint_auth_method:   "client_secret_basic",
			Contacts:                     []string{"admin@example.org"},
			Registration_access_token:    "testRegToken",
		}
		assertCorrectMessage(t, got, got)
	})
}

func TestKeyEndpointPost(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get map[string]string, want map[string]string) {

		empJSON, err := json.Marshal(get)
		if err != nil {
			log.Fatalf(err.Error())
		}
		//pass request to handler with nil as parameter
		req, err := http.NewRequest("POST", "/oauth/keys", bytes.NewBuffer(empJSON))
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		httpRecorder := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.KeyEndpoint)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(httpRecorder, req)
		bodybytes := httpRecorder.Body
		jmap, err := ijson.StructToJson(bodybytes)
		//bodyBytes, err := io.ReadAll(rr.Body)
		if err != nil {
			log.Fatal(err)
		}

		jsonStr, err := json.Marshal(jmap)
		if err != nil {
			log.Fatal(err)
		}

		// convert json to struct
		var keys map[string]string
		err = json.Unmarshal(jsonStr, &keys)
		if err != nil {
			log.Fatal(err)
		}
	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := map[string]string{"s": `-----BEGIN RSA PRIVATE KEY-----
		MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
		KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
		o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
		TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
		9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
		v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
		/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
		-----END RSA PRIVATE KEY-----`}

		assertCorrectMessage(t, got, got)
	})
}

func TestKeyEndpointGet(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get, want string) {

	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := ""

		assertCorrectMessage(t, got, got)
	})
}

func TestKeyEndpointDelete(t *testing.T) {

	assertCorrectMessage := func(t testing.TB, get, want string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("DELETE", "/oauth/keys/{kid}", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("kid", "testKid")

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		handlers := http.HandlerFunc(bs.KeyEndpoint)

		handlers(w, r)
	}
	t.Run("Registration Test 1", func(t *testing.T) {
		got := ""

		assertCorrectMessage(t, got, got)
	})

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

		clientConfig := ClientConfig{Method: "RS256", Claims: testclaims, Kid: sig.String()}
		signedToken, err := CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
		if err != nil {
			log.Fatal(err)
		}
		//pass request to handler with nil as parameter
		req, err := http.NewRequest("GET", "/oauth/clients", bytes.NewBuffer(empJSON))
		req.Header.Set("Authorization", "Bearer "+signedToken)
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.Registration)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)
		bodybytes := rr.Body

		jmap, err := ijson.StructToJson(bodybytes)
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
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(jsonStr))

		// convert json to struct
		s := Registration{}
		err = json.Unmarshal(jsonStr, &s)
		if err != nil {
			log.Fatal(err)
		}
		if get.Client_id != want.Client_id {
			t.Errorf("got %q want %q", get, want)
		}
	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := Registration{
			Client_id:     "testClientID",
			Client_secret: "testClientSecret",
			Redirect_uris: []string{
				"https://client.example.org/callback",
				"https://client.example.org/callback2",
			},
			Grant_types:                  "openid",
			Response_types:               "openid",
			Id_token_signed_response_alg: "rs256",
			Subject_type:                 "test",
			Application_type:             "web",
			Client_name:                  "MyCoolApp",
			Logo_uri:                     "https://client.example.org/logo.png",
			Token_endpoint_auth_method:   "client_secret_basic",
			Contacts:                     []string{"admin@example.org"},
			Registration_access_token:    "testRegToken",
		}
		assertCorrectMessage(t, got, got)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
		got := Registration{
			Client_id:     "testClientID",
			Client_secret: "testClientSecret",
			Redirect_uris: []string{
				"https://client.example.org/callback",
				"https://client.example.org/callback2",
			},
			Grant_types:                  "openid",
			Response_types:               "openid",
			Id_token_signed_response_alg: "rs256",
			Subject_type:                 "test",
			Application_type:             "web",
			Client_name:                  "MyCoolApp",
			Logo_uri:                     "https://client.example.org/logo.png",
			Token_endpoint_auth_method:   "client_secret_basic",
			Contacts:                     []string{"admin@example.org"},
			Registration_access_token:    "testRegToken",
		}
		assertCorrectMessage(t, got, got)

	})
}

func TestGetRedirect(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, got, want map[string]interface{}) {
		t.Helper()
		form := url.Values{}
		form.Add("name", "tester")
		form.Add("password", "testpw")
		req, err := http.NewRequest("POST", "/oauth/auth?client_id=ww&nonce=ww&response_type=id_token&scope=ww&redirect_uri=www.url.de&state=ww", bytes.NewBufferString(form.Encode()))
		//req.PostForm = form
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.GetRedirect)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)
		bodybytes := rr.Header().Get("Location")
		if bodybytes == "" {
			t.Errorf("json encoding failed %v", err)
		}

	}
	t.Error()
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
	req.Header.Add("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5uZXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIEFkYW1zIiwiYXVkIjoiMDAwMTIzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL2MyaWQiLCJmYW1pbHlfbmFtZSI6IkFkYW1zIiwiaWF0IjoxNDEzOTg1NDAyLCJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfQ.FJv9UnxvQxYvlc2F_v657SIyZkjQ382Bc108O--UFh3cvkjxiO5P2sJyvcqfuGrlzgvU7gCKzTIqqrV74EcHwGb_xyBUPOKuIJGaDKirBdnPbIXMDGpSqmBQes4tc6L8pkhZfRENIlmkP-KphI3wPd4jtko2HXAdDFVjzK-FPic")
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
	//t.Error()

}

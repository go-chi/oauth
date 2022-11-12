package oauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSignIn(t *testing.T) {
	data := url.Values{}
	data.Set("password", "testpw2")
	data.Set("client_id", "test_client")
	data.Set("response_type", "code")
	data.Set("redirect_uri", "testredirecturl")
	data.Set("scope", "testscope")
	data.Set("nonce", "testnonce")
	data.Set("state", "teststate")
	assertCorrectMessage := func(t testing.TB, data url.Values, get, want string) {

		req, err := http.NewRequest("GET", "/users/sign_in", bytes.NewBufferString(data.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+signedToken)
		if err != nil {
			t.Fatal(err)
		}
		formMap := map[string][]string{"client_id": {"test_client"}, "nonce": {"testnonce"},
			"redirect_uri": {"http://localhost:8080"}, "response_type": {"code"}, "scope": {"testscope"},
			"state": {"teststate"}}
		qAddList(req, formMap)

		rw := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.SignIn)
		handler.ServeHTTP(rw, req)

		t.Error(rw)
	}
	t.Run("Registration Test 1", func(t *testing.T) {
		data := url.Values{}
		got := ""

		assertCorrectMessage(t, data, got, got)
	})

	t.Run("Registration Test 1", func(t *testing.T) {

		data.Set("name", "dwight")
		got := ""

		assertCorrectMessage(t, data, got, got)
	})

}

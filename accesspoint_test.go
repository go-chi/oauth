package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignIn(t *testing.T) {
	req, err := http.NewRequest("GET", "/users/sign_in", nil)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+signedToken)
	if err != nil {
		t.Fatal(err)
	}

	assertCorrectMessage := func(t testing.TB, formMap map[string][]string, want int) {
		qAddList(req, formMap)
		rw := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.SignIn)
		handler.ServeHTTP(rw, req)

		if rw.Code != want {
			t.Error(rw.Body.String())
		}
	}
	t.Run("Sign in Test no client_id", func(t *testing.T) {
		formMap := map[string][]string{"nonce": {"testnonce"},
			"redirect_uri": {"http://localhost:8080"}, "response_type": {"code"}, "scope": {"testscope"},
			"state": {"teststate"}}
		want := 403

		assertCorrectMessage(t, formMap, want)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
		formMap := map[string][]string{"client_id": {"test_client"}, "nonce": {"testnonce"},
			"redirect_uri": {"http://localhost:8080"}, "response_type": {"code"}, "scope": {"testscope"},
			"state": {"teststate"}}
		want := http.StatusFound

		assertCorrectMessage(t, formMap, want)
	})

}

func TestRedirectAccess(t *testing.T) {

	req, err := http.NewRequest("GET", "/users/sign_in", nil)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+signedToken)
	if err != nil {
		t.Fatal(err)
	}

	assertCorrectMessage := func(t testing.TB, formMap map[string][]string, want int) {
		qAddList(req, formMap)
		rw := httptest.NewRecorder()
		RedirectAccess(bs, rw, req)
		fmt.Println(len(rw.Body.String()))

		if rw.Code != want {
			t.Error(rw.Body.String())
		}
	}

	t.Run("Registration Test 1", func(t *testing.T) {
		formMap := map[string][]string{"client_id": {"test_client"}, "nonce": {"testnonce"},
			"redirect_uri": {"http://localhost:8080"}, "response_type": {"code"}, "scope": {"testscope"},
			"state": {"teststate"}}
		want := 403

		assertCorrectMessage(t, formMap, want)
	})

	t.Run("Registration Test 1", func(t *testing.T) {
		formMap := map[string][]string{"client_id": {"test_client"}, "nonce": {"testnonce"},
			"redirect_uri": {"http://localhost:8080"}, "response_type": {"code"}, "scope": {"testscope"},
			"state": {"teststate"}}
		want := http.StatusOK

		assertCorrectMessage(t, formMap, want)
	})

}

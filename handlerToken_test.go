package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestTokenEndpoint(t *testing.T) {
	req, err := http.NewRequest("POST", "/oauth/clients", nil)
	if err != nil {
		t.Errorf("json encoding failed %v", err)
	}
	q := req.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", "")
	q.Add("redirect_uri", "http://localhost:8080")

	clientId := "clientID"
	token, refreshToken, idtoken, err := bs.generateIdTokens("RS256", clientId, UserToken, "user111", "openid", "", []string{"group1"}, at, req)

	t.Run("TokenEndPoint Test 1", func(t *testing.T) {
		assertNoError(t, err)
	})
	t.Run("TokenEndPoint Test 2", func(t *testing.T) {
		assertEmptyString(t, token)
	})
	t.Run("TokenEndPoint Test 3", func(t *testing.T) {
		assertEmptyString(t, idtoken)
	})
	t.Run("TokenEndPoint Test 4", func(t *testing.T) {
		assertString(t, refreshToken.TokenID, clientId)
	})
	t.Run("TokenEndPoint Test 5", func(t *testing.T) {
		//token, refreshToken, idtoken, err := bs.generateIdTokens("RS256", clientId, UserToken, "user111", "openid", "", []string{"group1"}, at, req)

		assertString(t, refreshToken.TokenID, clientId)
	})
}

func TestTokenIntrospect(t *testing.T) {
	var at AuthToken
	t.Run("Get jwt from Header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/oauth/introspect", nil)
		mux := chi.NewRouter()
		mux.Post("/oauth/introspect", bs.TokenIntrospect)
		ts := httptest.NewTLSServer(mux)
		groups := []string{"group1", "group2"}
		scope := []string{"scope1", "scope2"}
		claims := bs.verifier.CreateAtClaims("TestclientID", "username", "aud", bs.nonce, scope, groups, at, req)

		access_token, _ := CreateJWT("RS256", claims, bs.Kc)
		dd := url.Values{"token": {access_token}}
		resp, err := ts.Client().PostForm(ts.URL+"/oauth/introspect", dd)
		if err != nil {
			t.Errorf("json encoding failed %v", err)
		}
		obj := make(map[string]interface{})
		ConvertIOReader(resp.Body, &obj)
		for i, v := range obj {
			if (i != "sub") && (i != "iat") && (i != "iss") && (i != "jti") && (i != "active") && (i != "scope") && (i != "client_id") {
				if i == "active" && v != true {
					t.Error(err)
				}
			}
		}
	})

	t.Run("Get jwt from Header", func(t *testing.T) {
		mux := chi.NewRouter()
		mux.Post("/oauth/introspect", bs.TokenIntrospect)
		ts := httptest.NewTLSServer(mux)
		dd := url.Values{"token": {"test", "test2"}}
		_, err := ts.Client().PostForm(ts.URL+"/oauth/introspect", dd)
		if err != nil {
			t.Errorf("json encoding failed %v", err)
		}

	})

}

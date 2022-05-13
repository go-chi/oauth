package oauth

import (
	"fmt"
	"net/http"
	"testing"
)

func TestGenerateIdTokensByUsername(t *testing.T) {
	r := new(http.Request)
	token, refresh, idtoken, err := _sut.generateidTokens(UserToken, "user111", "openid", r)

	if idtoken == "nil" {
		fmt.Println(idtoken)
	}

	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
		t.Logf("IdToken: %v", idtoken)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}
func TestGenerateIdToken4Password(t *testing.T) {

	resp, code := _sut.generateIdTokenResponse(PasswordGrant, "user111", "password111", "", "", "", "", new(http.Request))
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}
	t.Logf("Token response: %v", resp)
	t.Error()
}

func TestClientIdCredentials(t *testing.T) {

}

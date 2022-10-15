package oauth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
)

func TestGenerateIdToken4Password(t *testing.T) {
	var at = AuthToken{}
	resp, code, err := _sut.GenerateIdTokenResponse("RS256", "", PasswordGrant, "", "", "", "", at, *new(http.ResponseWriter), new(http.Request))
	if err != nil {
		log.Err(err)
	}

	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}

	t.Logf("Token response: %v", resp)
	t.Error()
}

func TestGenerateIdTokenAuthCodeGrant(t *testing.T) {
	var at = AuthToken{}
	resp, code, err := _sut.GenerateIdTokenResponse("RS256", "", ClientCredentialsGrant, "", "", "", "", at, *new(http.ResponseWriter), new(http.Request))
	if err != nil {
		log.Err(err)
	}

	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}

	t.Logf("Token response: %v", resp)

}
func TestGenerateRefreshTokenGrant(t *testing.T) {}

func TestGenerateIdTokensByUsername(t *testing.T) {
	var at = AuthToken{}
	r := new(http.Request)
	token, refresh, idtoken, err := _sut.generateIdTokens("RS256", "", UserToken, "user111", "openid", "", []string{"group1"}, at, r)

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
	t.Error()
}

func TestClientIdCredentials(t *testing.T) {

}

func TestRefreshToken(t *testing.T) {

}

func TestGenerateIdTokens(t *testing.T) {
	//generateIdTokens()
}

func TestCryptIdTokens(t *testing.T) {
	var token *Token
	token.Claims = map[string]string{}
	token.CreationDate = time.Now()
	token.ExpiresIn = time.Minute
	token.Credential = "secret"
	token.ID = "ID2"
	token.Scope = ""
	token.TokenType = ""

	var rToken *RefreshToken

	rToken.CreationDate = time.Now()
	rToken.Credential = "secret"
	rToken.Scope = ""
	rToken.TokenType = ""
	rToken.RefreshTokenID = ""
	rToken.TokenID = ""
	rToken.TokenType = ""
	//idToken := "eeee"

	_, err := http.NewRequest("GET", "/health-check", nil)
	if err != nil {
		t.Fatal(err)
	}

	//cToken, err := bs.cryptIdTokens(token, rToken, idToken, req)

	//fmt.Println(cToken.IDtoken)

}

func TestIntToBytes(t *testing.T) {
	var ints = []int{1, 99}

	for _, v := range ints {
		bytess := IntToBytes(v)
		var a byte
		err := binary.Read(bytes.NewReader(bytess[3:]), binary.BigEndian, &a)
		r := int(a)
		if r != v || err != nil {
			t.Error(v)
		}
	}
}

package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid"
)

func TestGenerateIdTokenResponse(t *testing.T) {}

func TestGenToken(t *testing.T) {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signature, err := uuid.FromBytes(privatekey.PublicKey.N.Bytes())
	if err != nil {
		t.Error()
	}

	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
		privatekey,
		signature.String(),
	)
	username := "John"
	scope := "scope"
	var tokenType TokenType = "Bearer"

	token := GenToken(bs, username, tokenType, scope)

	if token.Claims != nil {
		t.Error()
	}
}

func TestRefreshToken(t *testing.T) {

	var tokenId string = "ID"
	var username string = "ID"
	var tokenType TokenType = "ID"
	var scope string = "ID"

	refreshToken := refreshToken(tokenId, username, tokenType, scope)

	if refreshToken.Scope != "" {
		t.Error()
	}
}

func TestGenerateIdTokensByUsername(t *testing.T) {
	r := new(http.Request)
	token, refresh, idtoken, err := _sut.generateIdTokens(UserToken, "user111", "openid", r)

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
func TestGenerateIdToken4Password(t *testing.T) {

	resp, code := _sut.GenerateIdTokenResponse(PasswordGrant, "user111", "password111", "", "", "", "", new(http.Request))
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

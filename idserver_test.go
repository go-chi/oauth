package oauth

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
)

func TestGenerateIdToken4Password(t *testing.T) {
	var at = AuthToken{}
	qq := CodeCheck{}
	resp, code, err := _sut.GenerateIdTokenResponse(qq, "RS256", at.Aud, PasswordGrant, "refreshToken", "scope", "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJhZGMzNTk3LThmOWUtNDI5OS05Zjg3LWY5NGM2NzM1YzY4YyIsInR5cCI6IkpXVCJ9.eyJmb28iOiJjbiIsIm5vbmNlIjoiZHdpZ2h0IiwiZ3JvdXBzIjpudWxsLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiZHdpZ2h0IiwiYXVkIjpbInRlc3RfY2xpZW50SWQiXSwiZXhwIjoxNjY4Mzc0MzY5LCJuYmYiOjE2NjgyODc5NjcsImlhdCI6MTY2ODI4Nzk2OSwianRpIjoiMSJ9.bOFpngRoS65q2blTqUEa7cAJ7KVijNU3yh7ayCdcmF3rPLcx47xO33zdOFYvbYW4dtNJQZrk2TWb9kFT_oqidXWmlxWDTD1adP3Rbny1Pi5JkzBi8GCYHU17hhX1sV4VQZHD1pdwv9lyJY_JOsqFI5hYxBGgmpDBaHN8xnxDJdPr9VTM6filhKyG8Eaq08j5BZXsw4EW-f0j3KFCITtAPtgK6PXBLH4294FoiL_jbYp97Eh9FbbZrbxfx1c8yIqIqDsXRTsf6z8dZ0BZhLc0xYIy6PgoxdrnR4htTTU99gDw2v2l76_v2txMn72DvYa-N-jnbtFEz0uB-LVAd_Qvuw", "redirectURI", at, *new(http.ResponseWriter), new(http.Request))
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
	qq := CodeCheck{}
	resp, code, err := _sut.GenerateIdTokenResponse(qq, "RS256", at.Aud, ClientCredentialsGrant, "", "", "", "", at, *new(http.ResponseWriter), new(http.Request))
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
	token, refresh, idtoken, err := _sut.generateIdTokens("RS256", at.Aud, UserToken, "user111", "openid", "", []string{"group1"}, at, r)

	if idtoken == "nil" {
		log.Warn().Msgf("Idtoken is: %s", idtoken)
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

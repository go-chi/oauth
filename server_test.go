package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

var _sut = NewBearerServer(
	"mySecretKey-10101",
	time.Second*60,
	new(TestUserVerifier),
	nil,
)

// TestUserVerifier provides user credentials verifier for testing.
type TestUserVerifier struct {
}

func (*TestUserVerifier) UserLookup(username, password, scope string) (map[string]string, error) {
	return nil, nil
}
func (TestUserVerifier) AddIdClaims() (map[string]string, error) {
	return map[string]string{}, nil
}

func (TestUserVerifier) CreateClaims(nonce string, r *http.Request) MyCustomClaims {

	return MyCustomClaims{}
}

// Validate username and password returning an error if the user credentials are wrong
func (TestUserVerifier) ValidateUser(username, password, scope string, r *http.Request) error {
	// Add something to the request context, so we can access it in the claims and props funcs.
	ctx := r.Context()
	ctx = context.WithValue(ctx, "oauth.claims.test", "test")
	ctx = context.WithValue(ctx, "oauth.props.test", "test")
	*r = *r.Clone(ctx)
	fmt.Print("sss")
	switch {
	case username == "user111" && password == "password111":
		return nil
	case username == "user222" && password == "password222":
		return nil
	case username == "user333" && password == "password333":
		return nil
	default:
		return errors.New("wrong user")
	}
}

// Validate clientID and secret returning an error if the client credentials are wrong
func (TestUserVerifier) ValidateClient(clientID, clientSecret, scope string, r *http.Request) error {
	// Add something to the request context, so we can access it in the claims and props funcs.
	ctx := r.Context()
	ctx = context.WithValue(ctx, "oauth.claims.test", "test")
	ctx = context.WithValue(ctx, "oauth.props.test", "test")
	*r = *r.Clone(ctx)

	if clientID == "abcdef" && clientSecret == "12345" {
		return nil
	}
	return errors.New("wrong client")
}

// Provide additional claims to the token
func (TestUserVerifier) AddClaims(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customer_id"] = "1001"
	claims["customer_data"] = `{"order_date":"2016-12-14","order_id":"9999"}`

	// Get value from request context, and add it to our claims.
	test := r.Context().Value("oauth.claims.test")
	if test != nil {
		claims["ctx_value"] = test.(string)
	}
	return claims, nil
}

// Provide additional information to the token response
func (TestUserVerifier) AddProperties(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	props := make(map[string]string)
	props["customer_name"] = "Gopher"

	// Get value from request context, and add it to our props.
	test := r.Context().Value("oauth.props.test")
	if test != nil {
		props["ctx_value"] = test.(string)
	}
	return props, nil
}

// Validate token ID
func (TestUserVerifier) ValidateTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) (bool, error) {
	fmt.Println(tokenType)

	return false, nil
}

// Optionally store the token ID generated for the user
func (TestUserVerifier) StoreTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

func (*TestUserVerifier) ValidateJwt(token string) (bool, error) {
	return false, nil
}

func TestGenerateTokensByUsername(t *testing.T) {
	r := new(http.Request)
	token, refresh, err := _sut.generateTokens(UserToken, "user111", "", r)
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestCryptTokens(t *testing.T) {
	r := new(http.Request)
	token, refresh, err := _sut.generateTokens(UserToken, "user222", "", r)
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}

	resp, err := _sut.cryptTokens(token, refresh, r)
	if err == nil {
		t.Logf("Response: %v", resp)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestDecryptRefreshTokens(t *testing.T) {
	r := new(http.Request)
	token, refresh, err := _sut.generateTokens(UserToken, "user333", "", r)
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}

	resp, err := _sut.cryptTokens(token, refresh, r)
	if err == nil {
		t.Logf("Response: %v", resp)
		t.Logf("Response Refresh Token: %v", resp.RefreshToken)
	} else {
		t.Fatalf("Error %s", err.Error())
	}

	refresh2, err := _sut.provider.DecryptRefreshTokens(resp.RefreshToken)
	if err == nil {
		t.Logf("Refresh Token Decrypted: %v", refresh2)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestGenerateToken4Password(t *testing.T) {
	resp, code := _sut.generateTokenResponse(PasswordGrant, "user111", "password111", "", "", "", "", new(http.Request))
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}
	t.Logf("Token response: %v", resp)
}

func TestShouldFailGenerateToken4Password(t *testing.T) {
	_, code := _sut.generateTokenResponse(PasswordGrant, "user111", "password4444", "", "", "", "", new(http.Request))
	t.Logf("Server response: %v", code)
	if code != 401 {
		t.Fatalf("Error StatusCode = %d", code)
	}
}

func TestGenerateToken4ClientCredentials(t *testing.T) {
	resp, code := _sut.generateTokenResponse(ClientCredentialsGrant, "abcdef", "12345", "", "", "", "", new(http.Request))
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}
	t.Logf("Token response: %v", resp)
}

func TestRefreshToken4ClientCredentials(t *testing.T) {
	r := new(http.Request)
	resp, code := _sut.generateTokenResponse(ClientCredentialsGrant, "abcdef", "12345", "", "", "", "", r)
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	if resp.(*TokenResponse).Properties["ctx_value"] != "test" {
		t.Fatalf("Error ctx_value invalid = %s", resp.(*TokenResponse).Properties["ctx_value"])
	}
	t.Logf("Token Response: %v", resp)
	resp2, code2 := _sut.generateTokenResponse(RefreshTokenGrant, "", "", resp.(*TokenResponse).RefreshToken, "", "", "", r)
	if code2 != 200 {
		t.Fatalf("Error StatusCode = %d", code2)
	}
	t.Logf("New Token Response: %v", resp2)
}

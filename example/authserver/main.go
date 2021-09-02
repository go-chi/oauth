package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/oauth"
)

/*
   Authorization Server Example

    Generate Token using username & password

    	POST http://localhost:3000/token
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 50
		Content-Type: application/x-www-form-urlencoded

		grant_type=password&username=user01&password=12345

	Generate Token using clientId & secret

    	POST http://localhost:3000/auth
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 66
		Content-Type: application/x-www-form-urlencoded

		grant_type=client_credentials&client_id=abcdef&client_secret=12345

	RefreshTokenGrant Token

		POST http://localhost:3000/token
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 50
		Content-Type: application/x-www-form-urlencoded

		grant_type=refresh_token&refresh_token={the refresh_token obtained in the previous response}

*/
func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "DNT", "Host", "Origin", "Pragma", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	registerAPI(r)
	_ = http.ListenAndServe(":8080", r)
}

func registerAPI(r *chi.Mux) {
	s := oauth.NewOAuthBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil)
	r.Post("/token", s.UserCredentials)
	r.Post("/auth", s.ClientCredentials)
}

// TestUserVerifier provides user credentials verifier for testing.
type TestUserVerifier struct {
}

// ValidateUser validates username and password returning an error if the user credentials are wrong
func (*TestUserVerifier) ValidateUser(username, password, scope string, req *http.Request) error {
	if username == "user01" && password == "12345" {
		return nil
	}
	return errors.New("Wrong user")
}

// ValidateClient validates clientId and secret returning an error if the client credentials are wrong
func (*TestUserVerifier) ValidateClient(clientID, clientSecret, scope string, req *http.Request) error {
	if clientID == "abcdef" && clientSecret == "12345" {
		return nil
	}
	return errors.New("Wrong client")
}

// AddClaims provides additional claims to the token
func (*TestUserVerifier) AddClaims(ctx context.Context, tokenType oauth.TokenType, credential, tokenID, scope string) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customerId"] = "1001"
	claims["customerData"] = `{"OrderDate":"2016-12-14","OrderId":"9999"}`
	return claims, nil
}

// StoreTokenId saves the token id generated for the user
func (*TestUserVerifier) StoreTokenID(tokenType oauth.TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

// AddProperties provides additional information to the token response
func (*TestUserVerifier) AddProperties(ctx context.Context, tokenType oauth.TokenType, credential, tokenID, scope string) (map[string]string, error) {
	props := make(map[string]string)
	props["customerName"] = "Gopher"
	return props, nil
}

// ValidateTokenId validates token ID
func (*TestUserVerifier) ValidateTokenID(tokenType oauth.TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

// ValidateCode validates token ID
func (*TestUserVerifier) ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error) {
	return "", nil
}

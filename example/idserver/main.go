package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/christhirst/oauth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
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

		Generate Token using clientID & secret

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
	_ = http.ListenAndServe(":8090", r)
}

type MyHandler struct {
}

func (h *MyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//...use h.Session to query the database...
}

func registerAPI(r *chi.Mux) {

	s := oauth.NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
	)

	r.Get("/users/sign_in", s.SignIn)
	r.HandleFunc("/oauth/clients/{id}", s.Registration)
	r.Get("/oauth/clients", s.Registration)
	r.HandleFunc("/oauth/mappings/{id}", s.Registration)
	r.Post("/oauth/token", s.TokenEndpoint)
	r.Post("/oauth/introspect", s.TokenIntrospect)
	r.Post("/oauth/revoke", s.TokenRevocation)
	r.HandleFunc("/oauth/auth", s.GetRedirect)
	r.Get("/oauth/authorize", s.SignIn)
	r.Get("/oauth/userinfo", s.UserInfo)
	r.Get("/oauth/keys", s.ReturnKeys)
	r.HandleFunc("/oauth/keys/{kid}", s.KeyEndpoint)
	r.Get("/oauth/.well-known/openid-configuration", s.OpenidConfig)
	//r.Get("/login", s.SignIn)
	r.Handle("/login", s)

	//th := http.HandlerFunc(s.SignIn)
	//r.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt))
	//fs := http.FileServer(http.Dir("./static/"))
	// Set up static file serving
	//staticPath, _ := filepath.Abs("./static/login.html")
	//fs := http.FileServer(http.Dir(staticPath))
	//r.Handle("/static/", http.StripPrefix("/static", fs))
	//r.Handle("/*", fs)

}

// TestUserVerifier provides user credentials Verifier for testing.
type TestUserVerifier struct {
}

/* func (TestUserVerifier) AddIdClaims() (map[string]string, error) {
	return map[string]string{}, nil
} */

// delete request for hostname
func (TestUserVerifier) CreateClaims(username string, aud []string, nonce string, groups []string, at oauth.AuthToken, r *http.Request) oauth.MyCustomClaims {
	scheme := "https://"
	baseURL := scheme + r.Host

	claims := oauth.MyCustomClaims{
		Foo:    "bars",
		Nonce:  nonce,
		Groups: groups,

		RegisteredClaims: jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    baseURL + "",
			Subject:   "somebody",
			ID:        "1",
			Audience:  at.Aud,
		},
	}
	return claims
}

/* func (TestUserVerifier) CreateAtClaims(client_id, username string, aud []string, nonce string, scope, groups []string, at oauth.AuthToken, r *http.Request) oauth.MyCustomClaimss {
	scheme := "https://"
	baseURL := scheme + r.Host

	claims := oauth.MyCustomClaimss{
		RegisteredClaims: jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    baseURL + "",
			Subject:   "somebody",
			ID:        "1",
			Audience:  at.Aud,
		},
	}
	return claims
} */

// ValidateUser validates username and password returning an error if the user credentials are wrong
func (*TestUserVerifier) ValidateUser(username, password, scope string, r *http.Request) ([]string, error) {
	if username == "Aaliyah" && password == "12345" {
		return []string{"group1", "group2", "group3", "group4"}, nil
	}

	return []string{"group1", "group2", "group3", "group4"}, errors.New("wrong user")
}

func (TestUserVerifier) GetUserData(username, password, scope string, r *http.Request) (map[string]string, error) {
	// Add something to the request context, so we can access it in the claims and props funcs.
	return nil, nil
}

// ValidateClient validates clientID and secret returning an error if the client credentials are wrong
func (*TestUserVerifier) ValidateClient(clientID, clientSecret string) error {
	if clientID == "abcdef" && clientSecret == "12345" {
		return nil
	}

	return errors.New("wrong client")
}

// ValidateCode validates token ID
func (*TestUserVerifier) ValidateCode(sub string, clientID, clientSecret, code, redirectURI string, r *http.Request) (string, error) {
	fmt.Println(sub)

	return "", nil
}

// AddClaims provides additional claims to the token
func (*TestUserVerifier) AddClaims(tokenType oauth.TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customer_id"] = "1001"
	claims["customer_data"] = `{"order_date":"2016-12-14","order_id":"9999"}`
	return claims, nil
}

// AddProperties provides additional information to the token response
func (*TestUserVerifier) AddProperties(tokenType oauth.TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	props := make(map[string]string)
	props["customer_name"] = "Gopher"
	return props, nil
}

func (*TestUserVerifier) ExtractJWTtoUserGroup(jwt string) ([]string, error) {
	userResp := []string{"group1", "group2"}

	return userResp, nil
}

// StoreTokenID saves the token id generated for the user
func (*TestUserVerifier) StoreTokenID(tokenType oauth.TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

func (*TestUserVerifier) UserLookup(username string, scope []string) (map[string]string, []string, error) {
	return nil, nil, nil
}

func (*TestUserVerifier) GetConnectionTarget(r *http.Request) (string, *oauth.AuthTarget, error) {
	return "false", &oauth.AuthTarget{}, nil
}

func (*TestUserVerifier) SessionSave(w http.ResponseWriter, r *http.Request, userID, cookieID string) (string, error) {

	return "", nil
}

func (*TestUserVerifier) SessionGet(w http.ResponseWriter, r *http.Request, cookieID string) (string, bool, error) {

	return "EmptyUser", false, nil
}

func (*TestUserVerifier) StoreClient(clientname string, client oauth.Registration, methode string) (*oauth.Registration, error) {

	var respInterface map[string]interface{}
	inrec, err := json.Marshal(client)
	if err != nil {
		log.Error().Err(err).Msg("Unable to marshal file")
	}
	err = json.Unmarshal(inrec, &respInterface)
	if err != nil {
		log.Error().Err(err).Msg("Unable to Unmarshal file")
	}
	return nil, nil
}

func (*TestUserVerifier) StoreClientGet(client string) (*oauth.Registration, error) {

	return nil, nil
}

func (*TestUserVerifier) StoreClientsGet() (map[string]*oauth.Registration, error) {

	//var respInterface map[string]interface{}
	/* inrec, _ := json.Marshal(clientId)
	json.Unmarshal(inrec, &respInterface)  */

	newMap := map[string]*oauth.Registration{}
	return newMap, nil
}

func (*TestUserVerifier) StoreClientDelete(clientId []string) error {
	return nil
}
func (*TestUserVerifier) StoreKeyDelete(kid []string) error { return nil }
func (*TestUserVerifier) StoreKey(map[string]string) error {
	return nil
}
func (*TestUserVerifier) StoreKeysGet() (map[string]rsa.PrivateKey, error) {
	return nil, nil
}

func (*TestUserVerifier) StoreKeysAppend(jwks []map[string]string) []map[string]string {
	return jwks
}

func (*TestUserVerifier) SignInMethod(string, http.ResponseWriter, *http.Request) error { return nil }
func (*TestUserVerifier) SignAdminInMethod(clientId string, w http.ResponseWriter, r *http.Request) (bool, error) {
	return true, nil
}

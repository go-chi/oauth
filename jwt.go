package oauth

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateJWT(method string, claims jwt.Claims, privatekey *rsa.PrivateKey, kid string) (string, error) {
	//switch method {
	//case "RS256":
	rt := jwt.GetSigningMethod(method)
	tokens := jwt.NewWithClaims(rt, claims)
	tokens.Header["kid"] = kid
	signedToken, err := tokens.SignedString(privatekey)

	if err != nil {
		fmt.Errorf("failed to parse token: %w", err)
	}
	if err != nil {
		log.Fatalf("Failed to create JWKS from JSON.\nError:%s", err.Error())
	}

	return signedToken, err
	//default:
	//	return "", errors.New("Failed creating jwt")
	//}

}

func CreateClaims(nonce string, r *http.Request) MyCustomClaims {
	//scheme := "https://"
	baseURL := scheme + r.Host
	claims := MyCustomClaims{
		"bars",
		nonce,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    baseURL + "",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"222"},
		},
	}
	return claims
}

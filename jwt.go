package oauth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
)

func GenKid() string {

	signature, err := uuid.NewV4()
	if err != nil {

	}
	return signature.String()

}

func CreateJWT(method string, claims jwt.Claims, kc *KeyContainer) (string, error) {
	//switch method {
	//case "RS256":
	rt := jwt.GetSigningMethod(method)
	tokens := jwt.NewWithClaims(rt, claims)
	tokens.Header["kid"] = kc.Keys.Keys[0]["kid"]
	signedToken, err := tokens.SignedString(kc.Pk)

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

func ParseJWT(jwtToken string, kc *KeyContainer) (string, error) {
	parsedToken, err := jwt.Parse(jwtToken, func(t *jwt.Token) (interface{}, error) { return kc.Pk.PublicKey, nil })
	if parsedToken.Valid {
		return "", errors.New("Token invalid")
	}

	claims := parsedToken.Claims.(jwt.MapClaims)
	if val, ok := claims["sub"]; ok {
		sub := val.(string)
		return sub, err
	}
	return "", err
}

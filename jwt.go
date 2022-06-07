package oauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
)

func GenKid() (string, error) {
	signature, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return signature.String(), nil
}

func CreateJWT(method string, claims jwt.Claims, kc *KeyContainer) (string, error) {
	//switch method {
	//case "RS256":
	rt := jwt.GetSigningMethod(method)
	tokens := jwt.NewWithClaims(rt, claims)
	tokens.Header["kid"] = kc.Keys.Keys[0]["kid"]
	signedToken, err := tokens.SignedString(kc.Pk)
	ParseJWT(signedToken, &kc.Pk.PublicKey)
	if err != nil {
		fmt.Printf("failed to parse token: %e", err)
	}
	if err != nil {
		log.Fatalf("Failed to create JWKS from JSON.\nError:%s", err.Error())
	}

	return signedToken, err
}

func CreateClaims(userdata map[string]string, nonce string, r *http.Request) MyCustomClaims {
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
	for i, v := range userdata {
		if i == "Subject" {
			claims.Subject = v
		}
	}

	return claims
}

func ParseJWT(jwtToken string, kc *rsa.PublicKey) (string, error) {
	parsedToken, err := jwt.Parse(jwtToken, func(t *jwt.Token) (interface{}, error) { return kc, nil })
	if !parsedToken.Valid {
		return "", errors.New("Token invalid")
	}

	claims := parsedToken.Claims.(jwt.MapClaims)
	if val, ok := claims["sub"]; ok {
		sub := val.(string)
		return sub, err
	}
	return "", err
}

/*
the "typ" value used SHOULD be   "at+jwt"

Data Structure

   The following claims are used in the JWT access token data structure.

   iss  REQUIRED - as defined in Section 4.1.1 of [RFC7519].

   exp  REQUIRED - as defined in Section 4.1.4 of [RFC7519].


Bertocci                Expires November 26, 2021               [Page 4]

Internet-Draft     OAuth 2.0 Access Token JWT Profile           May 2021


   aud  REQUIRED - as defined in Section 4.1.3 of [RFC7519].  See
      Section 3 for indications on how an authorization server should
      determine the value of "aud" depending on the request.

   sub  REQUIRED - as defined in Section 4.1.2 of [RFC7519].  In case of
      access tokens obtained through grants where a resource owner is
      involved, such as the authorization code grant, the value of "sub"
      SHOULD correspond to the subject identifier of the resource owner.
      In case of access tokens obtained through grants where no resource
      owner is involved, such as the client credentials grant, the value
      of "sub" SHOULD correspond to an identifier the authorization
      server uses to indicate the client application.  See Section 5 for
      more details on this scenario.  Also, see Section 6 for a
      discussion about how different choices in assigning "sub" values
      can impact privacy.

   client_id  REQUIRED - as defined in Section 4.3 of [RFC8693].

   iat  REQUIRED - as defined in Section 4.1.6 of [RFC7519].  This claim
      identifies the time at which the JWT access token was issued.

   jti  REQUIRED - as defined in Section 4.1.7 of [RFC7519].


Authentication Information Claims

   The claims listed in this section MAY be issued in the context of
   authorization grants involving the resource owner, and reflect in the
   access token the types and strength of authentication that the
   authentication server enforced prior to returning the authorization
   response to the client.  Their values are fixed, and remain the same
   across all access tokens that derive from a given authorization
   response, whether the access token was obtained directly in the
   response (e.g., via the implicit flow) or after one or more token
   exchanges (e.g., obtaining a fresh access token using a refresh
   token, or exchanging one access token for another via [RFC8693]
   procedures).

   auth_time  OPTIONAL - as defined in Section 2 of [OpenID.Core].

   acr  OPTIONAL - as defined in Section 2 of [OpenID.Core].

   amr  OPTIONAL - as defined in Section 2 of [OpenID.Core].





 GET /as/authorization.oauth2?response_type=code
           &client_id=s6BhdRkqt3
           &state=xyz
           &scope=openid%20profile%20reademail
           &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
           &resource=https%3A%2F%2Frs.example.com%2F HTTP/1.1
        Host: authorization-server.example.com


    Figure 1: Authorization Request with Resource and Scope Parameters

   Once redeemed, the code obtained from the request above will result
   in a JWT access token in the form shown below:






Bertocci                Expires November 26, 2021               [Page 7]

Internet-Draft     OAuth 2.0 Access Token JWT Profile           May 2021


   Header:

      {"typ":"at+JWT","alg":"RS256","kid":"RjEwOwOA"}

   Claims:

      {
        "iss": "https://authorization-server.example.com/",
        "sub": "5ba552d67",
        "aud":   "https://rs.example.com/",
        "exp": 1639528912,
        "iat": 1618354090,
        "jti" : "dbe39bf3a3ba4238a513f51d6e1691c4",
        "client_id": "s6BhdRkqt3",
        "scope": "openid profile reademail"
      }




*/

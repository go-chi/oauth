# oauth middleware
OAuth 2.0 Authorization Server &amp; Authorization Middleware for [go-chi](https://github.com/go-chi/chi)

This library was ported to go-chi from https://github.com/maxzerbini/oauth by [jeffreydwalter](https://github.com/jeffreydwalter/oauth).

This library offers an OAuth 2.0 Authorization Server based on go-chi and an Authorization Middleware usable in Resource Servers developed with go-chi.


## Build status
[![Build Status](https://app.travis-ci.com/go-chi/oauth.svg?branch=master)](https://app.travis-ci.com/github/go-chi/oauth)

## Authorization Server
The Authorization Server is implemented by the struct _OAuthBearerServer_ that manages two grant types of authorizations (password and client_credentials). 
This Authorization Server is made to provide an authorization token usable for consuming resources API. 

### Password grant type
_OAuthBearerServer_ supports the password grant type, allowing the token generation for username / password credentials.

### Client Credentials grant type
_OAuthBearerServer_ supports the client_credentials grant type, allowing the token generation for client_id / client_secret credentials.

### Authorization Code and Implicit grant type
These grant types are currently partially supported implementing AuthorizationCodeVerifier interface. The method ValidateCode is called during the phase two of the authorization_code grant type evalutations.

### Refresh token grant type
If authorization token will expire, the client can regenerate the token calling the authorization server and using the refresh_token grant type.

## Authorization Middleware 
The go-chi middleware _BearerAuthentication_ intercepts the resource server calls and authorizes only resource requests containing a valid bearer token.

## Token Formatter
Authorization Server crypts the token using the Token Formatter and Authorization Middleware decrypts the token using the same Token Formatter.
This library contains a default implementation of the formatter interface called _SHA256RC4TokenSecureFormatter_ based on the algorithms SHA256 and RC4.
Programmers can develop their Token Formatter implementing the interface _TokenSecureFormatter_ and this is really recommended before publishing the API in a production environment. 

## Credentials Verifier
The interface _CredentialsVerifier_ defines the hooks called during the token generation process.
The methods are called in this order:
- _ValidateUser() or ValidateClient()_ called first for credentials verification
- _AddClaims()_ used for add information to the token that will be encrypted
- _StoreTokenID()_ called after the token generation but before the response, programmers can use this method for storing the generated IDs
- _AddProperties()_ used for add clear information to the response

There is another method in the _CredentialsVerifier_ interface that is involved during the refresh token process. 
In this case the methods are called in this order:
- _ValidateTokenID()_ called first for TokenID verification, the method receives the TokenID related to the token associated to the refresh token
- _AddClaims()_ used for add information to the token that will be encrypted
- _StoreTokenID()_ called after the token regeneration but before the response, programmers can use this method for storing the generated IDs
- _AddProperties()_ used for add clear information to the response

## Authorization Server usage example
This snippet shows how to create an authorization server
```Go
func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)

    s := oauth.NewOAuthBearerServer(
        "mySecretKey-10101",
	time.Second*120,
	&TestUserVerifier{},
	nil)
	
    r.Post("/token", s.UserCredentials)
    r.Post("/auth", s.ClientCredentials)
    http.ListenAndServe(":8080", r)
}
```
See [/example/authserver/main.go](https://github.com/go-chi/oauth/blob/master/example/authserver/main.go) for the full example.

## Authorization Middleware usage example
This snippet shows how to use the middleware
```Go
    r.Route("/", func(r chi.Router) {
	// use the Bearer Authentication middleware
	r.Use(oauth.Authorize("mySecretKey-10101", nil))

	r.Get("/customers", GetCustomers)
	r.Get("/customers/{id}/orders", GetOrders)
    }
```
See [/example/resourceserver/main.go](https://github.com/go-chi/oauth/blob/master/example/resourceserver/main.go) for the full example.

Note that the authorization server and the authorization middleware are both using the same token formatter and the same secret key for encryption/decryption.

## Reference
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Bearer Token Usage RFC](https://tools.ietf.org/html/rfc6750)

## License
[MIT](https://github.com/go-chi/oauth/blob/master/LICENSE)

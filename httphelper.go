package oauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

func getFormData(formValues []string, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	for key, values := range r.Form { // range over map
		for _, value := range values { // range over []string
			fmt.Println(key, value)
		}
	}

}

func Unauthorized(bs *BearerServer, client_id string) (bool, error) {
	client, err := bs.verifier.StoreClientGet(client_id)
	if client != nil {
		return false, err
	}
	return true, err

}

func Forbidden(scope jwt.Claims) (bool, error) {
	return false, nil
}

func OpenIDConnectFlows(id_token, access_token, response_type, redirect_uri, state string, scope []string, w http.ResponseWriter, r *http.Request) {
	switch response_type {
	case "id_token":
		fmt.Println(111)
		location := redirect_uri + "?id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	case "code":
		fmt.Println(222)
		if slices.Contains(scope, "openid") {
			location := redirect_uri + "?code=" + access_token + "&state=" + state
			fmt.Println(location)
			w.Header().Add("Location", location)
			http.Redirect(w, r, location, 302)
		}
	case "id_token token": //insecure
		location := redirect_uri + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
	case "code id_token":
		fmt.Println(333)
		if slices.Contains(scope, "openid") {
			location := redirect_uri + "?code=" + access_token + "&state=" + state
			fmt.Println(location)
			w.Header().Add("Location", location)
			http.Redirect(w, r, location, 302)
		}
	case "code token": //insecure
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&state=" + state
		w.Header().Add("Location", location)
		//"code id_token token"
	case "code token id_token": //insecure
		fmt.Println("ssss")
		location := redirect_uri + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + state
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	default:
		fmt.Println("default")
	}
	//todo: OAuth client credentials flow; OAuth device flow

}

func UserData() (map[string]interface{}, int, string, error) {
	/* w.WriteHeader(401) // Unauthorized
	w.WriteHeader(403) // Forbidden
	w.WriteHeader(500) // Internal Server Error */

	we := map[string]string{"sub": "dd", "la": "ss"}

	s := make(map[string]interface{}, len(we))
	for i, v := range we {
		s[i] = v
	}

	return s, 200, "application/json", errors.New("")
}

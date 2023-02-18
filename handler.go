package oauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/christhirst/gohelper/ihttp"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

var refresh_token, redirect_uri string
var at AuthToken

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	//groups, err := bs.Verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	} */
	//iamAdmin := slices.Contains(groups, "group1")
	//ww, _ := bs.Verifier.SignAdminInMethod("", w, r)

	iamAdmin := true
	if iamAdmin {
		switch r.Method {
		case "GET":
			path := r.URL.Path
			base := strings.LastIndex(path, "/")
			clientID := path[base+1:]
			if path[:base+1] == "/oauth/" && clientID == "clients" {
				clients, err := bs.Verifier.StoreClientsGet()
				clientsList := []Registration{}
				for _, v := range clients {
					clientsList = append(clientsList, *v)
				}

				if err != nil {
					log.Error().Err(err).Msg("Unable to get clients")
				}
				renderJSON(w, clientsList, 200)
			} else if path[:base+1] == "/oauth/clients/" {
				client, err := bs.Verifier.StoreClientGet(clientID)
				if err != nil {
					log.Error().Err(err).Msgf("Unable to get client %s", client)
				}
				renderJSON(w, client, 200)
			} else {
				var clientConfig interface{}
				renderJSON(w, clientConfig, 401)
			}

		case "POST", "PUT":
			jsonMap := &Registration{}
			_, err := ihttp.ParseBody(r, jsonMap)
			if err != nil {
				log.Err(err)
				renderJSON(w, "Failed parsing client config", 422)
			}
			regResp, err := bs.Verifier.StoreClient(jsonMap.Client_name, *jsonMap, r.Method)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
				renderJSON(w, "Failed parsing client config", 422)
			}
			renderJSON(w, regResp, 200)
		case "DELETE":
			clientId := path.Base(r.URL.Path)

			err := bs.Verifier.StoreClientDelete([]string{clientId})
			if err != nil {
				renderJSON(w, "failed", 500)
			}
			renderJSON(w, "deleted: "+clientId, 200)
		default:
			log.Error().Msg("failed")
		}
	}
}

func (bs *BearerServer) ConnectionTargetEp(w http.ResponseWriter, r *http.Request) {
	if true {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.Verifier.StoreKeysGet()
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST":
			var keys map[string]string
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			err = json.Unmarshal(body, &keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			//err = bs.Verifier.
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":
			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.Verifier.StoreKeyDelete([]string{kid})
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		}
	}
}

func (bs *BearerServer) KeyEndpoint(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	groups, err := bs.Verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	iamAdmin := slices.Contains(groups, "group1") */

	if true {
		switch r.Method {
		case "GET":
			fmt.Println("uuu")
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.Verifier.StoreKeysGet()
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST":
			var keys map[string]string
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			err = json.Unmarshal(body, &keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			err = bs.Verifier.StoreKey(keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":

			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			fmt.Println(path.Base(r.URL.Path))
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.Verifier.StoreKeyDelete([]string{kid})
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		}
	}
}

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	formList := []string{"name", "password", "client_id", "response_type", "redirect_uri", "scope", "nonce", "state"}
	formMap, _, err := formExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form Value not present")
	}
	nonce := "code"
	if _, ok := formMap["nonce"]; ok {
		nonce = formMap["nonce"][0]
	}

	_, err = bs.Verifier.SessionSave(w, r, formMap["name"][0], "user_session")
	if err != nil {
		log.Error().Err(err).Msg("Failed saving session")
	}

	groups, err := bs.Verifier.ValidateUser(formMap["name"][0], formMap["password"][0], formMap["scope"][0], r)
	if err != nil {
		log.Error().Err(err).Msg("Failed validating user getting groups")
	}

	var authParameter = AuthToken{
		Iss:   formMap["client_id"][0],
		Sub:   formMap["client_id"][0],
		Aud:   formMap["client_id"],
		Nonce: nonce,
		//exp:       exp,
		//iat:       iat,
		//auth_time: auth_time,
		//acr:       acr,
		//azp:       azp,
	}

	claims := bs.Verifier.CreateClaims(formMap["name"][0], formMap["client_id"], nonce, groups, authParameter, r)
	access_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create access_token")
	}
	id_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}
	OpenIDConnectFlows(id_token, access_token, formMap["response_type"][0], formMap["redirect_uri"][0], formMap["state"][0], formMap["scope"], w, r)
}

type JWT struct {
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}
	headerEntry := strings.Split(r.Header.Get("Authorization"), " ")
	fmt.Println(headerEntry)
	if len(headerEntry) < 1 {
		renderJSON(w, nil, http.StatusForbidden)
		return
	}
	jwtToken := headerEntry[1]
	jwtSplit := strings.Split(jwtToken, ".")
	jwtHeader, _ := base64.RawStdEncoding.DecodeString(jwtSplit[0])

	jwtParsed := JWT{}
	err = json.Unmarshal(jwtHeader, &jwtParsed)
	if err != nil {
		fmt.Println("error:", err)
	}

	//bs.Kc.Pk[jwtParsed.Kid]
	_, ok := bs.Kc.Pk["test"]

	var pk *rsa.PublicKey
	if !ok {
		log.Error().Err(err).Msgf("Key not available: %s", jwtParsed.Kid)
	} else {
		//bs.Kc.Pk[jwtParsed.Kid]
		pk = &bs.Kc.Pk["test"].PublicKey
	}

	if ok {
		fmt.Println(jwtToken)
		fmt.Println(pk)
		parsedToken, err := JWTvalid(jwtToken, pk)
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Println(parsedToken.Claims)
		fmt.Println(jwt.MapClaims)
		ee := parsedToken.Claims.(jwt.MapClaims)
		username := ee["sub"].(string)

		//get userdata
		groups, err := bs.Verifier.ValidateUser(username, "password", "scope", r)
		if err != nil {
			log.Error().Err(err).Msg("Parsing Form failed")
		}
		fmt.Println(groups)
		jsonPayload, rc, contentType, err := UserData()
		if err != nil {
			log.Error().Err(err).Msg("Unable to create id_token")
		}
		w.Header().Set("Content-Type", contentType)
		renderJSON(w, jsonPayload, rc)
		return
	}

	renderJSON(w, nil, http.StatusForbidden)
}
func (bs *BearerServer) GetConnectionTarget(r *http.Request) (string, *AuthTarget, error) {
	return "false", &AuthTarget{}, nil
}

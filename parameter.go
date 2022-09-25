package oauth

import "github.com/golang-jwt/jwt/v4"

func parseScopes(parsedToken *jwt.Token) ([]string, error) {
	scope := parsedToken.Claims.(jwt.MapClaims)["scope"]
	scopes := []string{}
	for _, v := range scope.([]interface{}) {
		scopes = append(scopes, v.(string))
	}

	return scopes, nil
}

func parseClientid(parsedToken *jwt.Token) (string, error) {
	client_id := parsedToken.Claims.(jwt.MapClaims)["client_id"].(string)
	return client_id, nil
}

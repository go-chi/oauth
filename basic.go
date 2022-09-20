package oauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// GetBasicAuthentication get username and password from Authorization header
func GetBasicAuthentication(r *http.Request) (username, password string, err error) {
	if header := r.Header.Get("Authorization"); header != "" {
		if strings.ToLower(header[:6]) == "basic " {
			// decode header value
			value, err := base64.StdEncoding.DecodeString(header[6:])
			if err != nil {
				return "", "", err
			}
			strValue := string(value)
			if ind := strings.Index(strValue, ":"); ind > 0 {
				return strValue[:ind], strValue[ind+1:], nil
			}
		}
	}
	return "", "", errors.New("No user found")
}

// Check Basic Authorization header credentials
func CheckBasicAuthentication(username, password string, r *http.Request) error {
	u, p, err := GetBasicAuthentication(r)
	if err != nil {
		return err
	}
	if u != "" && p != "" && u != username && p != password {
		return errors.New("invalid credentials")
	}
	return nil
}

package oauth

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"
)

func TestGetBasicAuthentication(t *testing.T) {

	t.Run("Get jwt from Header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/token", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))
		want := []string{"admin", "password123456"}
		got := make([]string, 2)
		var err error
		got[0], got[1], err = GetBasicAuthentication(req)
		if err != nil {
			t.Fatalf("Error %s", err.Error())
		}

		assertResponseBody(t, got, want)
	})

	t.Run("Get jwt no user found", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/token", nil)
		username, password, err := GetBasicAuthentication(req)
		if err != ErrNoUserFound {
			t.Fatalf("Error %s", err.Error())
		} else {
			if username != "" {
				t.Fatalf("Wrong Username = %s", username)
			}
			if password != "" {
				t.Fatalf("Wrong Username = %s", password)
			}
		}
	})
}

func assertResponseBody(t testing.TB, got, want []string) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

/* func TestCheckBasicAuthentication(t *testing.T) {
	req, _ := http.NewRequest("GET", "/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))

	err := CheckBasicAuthentication("admin", "password123456", req)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		t.Log("Credentials are OK")
	}
}
*/

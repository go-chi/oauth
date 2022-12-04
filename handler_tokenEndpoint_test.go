package oauth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/christhirst/gohelper/ijson"
)

var tetests = []struct {
	name               string
	password           string
	grant_type         string
	params             []postData
	expectedStatusCode int
	Host               string
	Authorization      string
}{
	{"Aaliyah", "12345", "password",
		[]postData{}, http.StatusOK, "c2id.com",
		"Bearer SQvs1wv1NcAgsZomWWif0d9SDO0GKHYrUN6YR0ocmN0",
	},
}

func TestTokenEndpointPW(t *testing.T) {
	for _, v := range tetests {

		assertCorrectMessage := func(t testing.TB, got, want []string) {
			t.Helper()

			form := url.Values{}
			form.Add("name", v.name)
			form.Add("password", v.password)
			form.Add("grant_type", v.grant_type)

			req, err := http.NewRequest("POST", "/oauth/token", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.PostForm = form

			// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(bs.TokenEndpoint)

			//call ServeHTTP method and pass  Request and ResponseRecorder.
			handler.ServeHTTP(rr, req)
			bodybytes := rr.Body
			jmap, err := ijson.StructToJson(bodybytes)
			if err != nil {
				log.Fatal(err)
			}

			jsonStr, err := json.Marshal(jmap)
			if err != nil {
				log.Fatal(err)
			}

			// convert json to struct
			s := TokenResponse{}
			err = json.Unmarshal(jsonStr, &s)
			if err != nil {
				log.Fatal(err)
			}

			if s.IDtoken == "" || s.Token == "" {
				t.Errorf("got %v want %v", s.IDtoken, s.Token)
			}

		}

		t.Run("Registration Test 1", func(t *testing.T) {
			got := []string{"name", "tester", "password", "Aaliyah"}
			want := []string{"name", "tester"}
			assertCorrectMessage(t, got, want)
		})

	}
}

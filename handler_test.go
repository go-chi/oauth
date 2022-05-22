package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
)

/* "keys": [
   {
     "alg": "RS256",
     "e": "AQAB",
     "n": "iKqiD4cr7FZKm6f05K4r-GQOvjRqjOeFmOho9V7SAXYwCyJluaGBLVvDWO1XlduPLOrsG_Wgs67SOG5qeLPR8T1zDK4bfJAo1Tvbw
           YeTwVSfd_0mzRq8WaVc_2JtEK7J-4Z0MdVm_dJmcMHVfDziCRohSZthN__WM2NwGnbewWnla0wpEsU3QMZ05_OxvbBdQZaDUsNSx4
           6is29eCdYwhkAfFd_cFRq3DixLEYUsRwmOqwABwwDjBTNvgZOomrtD8BRFWSTlwsbrNZtJMYU33wuLO9ynFkZnY6qRKVHr3YToIrq
           NBXw0RWCheTouQ-snfAB6wcE2WDN3N5z760ejqQ",
     "kid": "U5R8cHbGw445Qbq8zVO1PcCpXL8yG6IcovVa3laCoxM",
     "kty": "RSA",
     "use": "sig"
   }, */

type postData struct {
	key   string
	value string
}

func TestReturnKeys(t *testing.T) {

	var theTests = []struct {
		name               string
		url                string
		method             string
		params             []postData
		expectedStatusCode int
	}{
		{"config", "/", "GET", []postData{}, http.StatusOK},
		{"config", "/config", "GET", []postData{}, http.StatusOK},
		{"config", "/config", "GET", []postData{}, http.StatusOK},
		{"load", "/load/mappings/FIRST3.json", "POST", []postData{
			{key: "start", value: "2022-01-01"},
			{key: "start", value: "2022-01-02"},
		}, http.StatusOK},
		{"load", "/load", "POST", []postData{
			{key: "start", value: "2022-01-01"},
			{key: "start", value: "2022-01-02"},
		}, http.StatusOK},
	}

	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signature, err := uuid.FromBytes(privatekey.PublicKey.N.Bytes())
	if err != nil {
		panic(err)
	}
	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
		privatekey,
		signature.String(),
	)

	mux := chi.NewRouter()
	mux.Get("/keys", bs.ReturnKeys)

	ts := httptest.NewTLSServer(mux)
	rs := map[string]int{"month": 12}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(rs); err != nil {
		panic(err)
	}
	for _, e := range theTests {

		if e.method == "GET" {
			resp, err := ts.Client().Get(ts.URL + e.url)
			if err != nil {
				t.Log(err)
				t.Fatal(err)
			}
			if resp.StatusCode != e.expectedStatusCode {
				t.Errorf("for %s, expected %d but got %d", e.name, e.expectedStatusCode, resp.StatusCode)
			}
		} else if e.method == "POST" {
			values := url.Values{}
			for _, x := range e.params {
				values.Add(x.key, x.value)
			}

			_, err := ts.Client().Post(ts.URL+e.url, "application/json", buf)
			if err != nil {
				t.Log(err)
				t.Fatal(err)
			}

		}

	}
	defer ts.Close()

}

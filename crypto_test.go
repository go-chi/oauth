package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReturnKeys(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.ReturnKeys)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	//ee := []map[string]string{{"alg": "ee"}, {"e": "ee"}, {"n": "ee"}, {"kid": "ee"}, {"kty": "ee"}, {"use": "ee"}}
	decoder := json.NewDecoder(rr.Body)
	var tsa Keys
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}

	for _, v := range tsa.Keys {
		for ii := range v {
			if (ii != "alg") && (ii != "e") && (ii != "n") && (ii != "kid") && (ii != "kty") && (ii != "use") {
				t.Error(err)
				t.Errorf("expected other key: %s but got: ", ii)
			}

		}
	}

}

func TestGenJWKS(t *testing.T) {
	ii := bs.Kc.Keys.Keys
	GenJWKS(bs.Kc)
	var keys []string

	for _, v := range ii {
		for ii := range v {
			keys = append(keys, ii)
		}
	}
	if len(keys) != 6 {
		t.Error()
	}
}

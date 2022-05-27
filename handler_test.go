package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

var pk, _ = rsa.GenerateKey(rand.Reader, 2048)
var sig, _ = uuid.FromBytes(pk.PublicKey.N.Bytes())

var bs = NewBearerServer(
	"mySecretKey-10101",
	time.Second*120,
	&TestUserVerifier{},
	nil,
	pk,
	sig.String(),
)

type postData struct {
	key   string
	value string
}

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
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa Keys
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}

	for _, v := range tsa.Keys {
		for ii, _ := range v {
			if (ii != "alg") && (ii != "e") && (ii != "n") && (ii != "kid") && (ii != "kty") && (ii != "use") {
				t.Error(err)
				t.Errorf("expected other key: %s but got: ", ii)
			}

		}
	}

}

func TestUserInfo(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.UserInfo)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa map[string]interface{}
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}
	fmt.Println(tsa)
	t.Error()

}

func TestUserData(t *testing.T) {
	groups := []string{"Admin", "User"}

	s := make([]interface{}, len(groups))
	for i, v := range groups {
		s[i] = v
	}
}

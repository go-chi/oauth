package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

func GenJWKS(kc *KeyContainer) {
	sEnc := base64.URLEncoding.EncodeToString(kc.Pk["test"].N.Bytes())
	bss := IntToBytes(kc.Pk["test"].E)
	eEnc := base64.URLEncoding.EncodeToString(bss)
	signature, err := uuid.NewV4()
	if err != nil {
		log.Err(err)
	}
	kc.Keys = Keys{[]map[string]string{{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": signature.String(), "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}
}

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {
	jwks := Keys{Keys: bs.Verifier.StoreKeysAppend(bs.Kc.Keys.Keys)}
	renderJSON(w, jwks, http.StatusOK)
}

/*
	 func PrivateKeyCreate(bitLength int) (privatekey *rsa.PrivateKey, err error) {
		privatekey, err = rsa.GenerateKey(rand.Reader, bitLength)
		return
	}
*/
func ConvertIOReader[k any](buff io.Reader, target k) {
	decoder := json.NewDecoder(buff)
	err := decoder.Decode(&target)
	if err != nil {
		panic(err)
	}
}
func ParseBody[t any](b io.ReadCloser, jsonTarget t) (t, error) {
	body, err := io.ReadAll(b)
	if err != nil {
		log.Error().Err(err).Msg("Unable to read body")
	}
	err = json.Unmarshal(body, &jsonTarget)
	if err != nil {
		log.Error().Err(err).Msg("Unable to Unmarshal file o")
	}
	fmt.Println(jsonTarget)
	return jsonTarget, err
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

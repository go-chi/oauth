package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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
	renderJSON(w, bs.Kc.Keys, http.StatusOK)
}

func PrivateKeyCreate(bitLength int) (privatekey *rsa.PrivateKey, err error) {
	privatekey, err = rsa.GenerateKey(rand.Reader, bitLength)
	return
}

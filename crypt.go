package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}
func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func PrivateKeyCreate(bitLength int) (privatekey *rsa.PrivateKey, err error) {
	privatekey, err = rsa.GenerateKey(rand.Reader, bitLength)
	return
}

func PrivateKeySave(privPEM string) {

}

func PrivateKeysLoad(privPEM string) {

}

func PrivateKeysDelete(privPEM string) {

}

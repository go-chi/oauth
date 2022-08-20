package oauth

import (
	"encoding/base64"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

func GenJWKS(kc *KeyContainer) {
	sEnc := base64.URLEncoding.EncodeToString(kc.Pk.N.Bytes())
	bss := IntToBytes(kc.Pk.E)
	eEnc := base64.URLEncoding.EncodeToString(bss)
	signature, err := uuid.NewV4()
	if err != nil {
		log.Err(err)
	}
	kc.Keys = Keys{[]map[string]string{{"alg": "RS256", "kty": "RSA", "use": "sig", "kid": signature.String(), "n": sEnc[:len(sEnc)-2], "e": eEnc[:len(eEnc)-2]}}}
}

func (bs *BearerServer) ReturnKeys(w http.ResponseWriter, r *http.Request) {

	renderJSON(w, bs.Kc.Keys, 200)
}

package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestKeySaveKeyPair(t *testing.T) {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2046)
	priv_pem := ExportRsaPrivateKeyAsPemStr(privatekey)

	parseKey, err := ParseRsaPrivateKeyFromPemStr(priv_pem)
	if err != nil {
		t.Error()
	}

	if !parseKey.Equal(privatekey) {
		t.Error()
	}

}

func TestKeyDeleteKeyPair(t *testing.T) {

}

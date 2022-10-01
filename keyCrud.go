package oauth

import (
	"crypto/rsa"
	"errors"
)

func keySaveKeyPair(kc *KeyContainer, kid string, privateKey string) error {
	//priv_pem, err := ParseRsaPrivateKeyFromPemStr(privateKey)

	kc.Keys.Keys = append(kc.Keys.Keys)
	return nil
}

func keyStringToKey(keyString string) (*rsa.PrivateKey, error) {

	return nil, nil
}

func keyDeleteKeyPair(kc *KeyContainer, kid string) error {
	newKeys := []map[string]string{{}}
	for _, v := range kc.Keys.Keys {
		if v["kid"] != kid {
			newKeys = append(newKeys, v)
		}
	}
	kc.Keys.Keys = newKeys
	if len(newKeys) == len(kc.Keys.Keys) {
		return errors.New("Key not found")
	}
	return nil
}
func keyStoreGet(kc *KeyContainer, kid string) {

}
func keyStoreSave(kc *KeyContainer, kid string) {

}

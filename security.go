package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type TokenSecureFormatter interface {
	CryptToken(source []byte) ([]byte, error)
	DecryptToken(source []byte) ([]byte, error)
}

type TokenProvider struct {
	secureFormatter TokenSecureFormatter
}

func NewTokenProvider(formatter TokenSecureFormatter) *TokenProvider {
	return &TokenProvider{secureFormatter: formatter}
}

func (tp *TokenProvider) CryptToken(t *Token) (token string, err error) {
	bToken, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tp.crypt(bToken)
}

func (tp *TokenProvider) CryptRefreshToken(t *RefreshToken) (token string, err error) {
	bToken, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tp.crypt(bToken)
}

func (tp *TokenProvider) DecryptToken(token string) (t *Token, err error) {
	bToken, err := tp.decrypt(token)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bToken, &t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (tp *TokenProvider) DecryptRefreshTokens(refreshToken string) (refresh *RefreshToken, err error) {
	bRefresh, err := tp.decrypt(refreshToken)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bRefresh, &refresh)
	if err != nil {
		return nil, err
	}
	return refresh, nil
}

func (tp *TokenProvider) crypt(token []byte) (string, error) {
	ctoken, err := tp.secureFormatter.CryptToken(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ctoken), nil
}

func (tp *TokenProvider) decrypt(token string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	return tp.secureFormatter.DecryptToken(b)
}

type RC4TokenSecureFormatter struct {
	key    []byte
	cipher *rc4.Cipher
}

func NewRC4TokenSecurityProvider(key []byte) *RC4TokenSecureFormatter {
	var sc = &RC4TokenSecureFormatter{key: key}
	return sc
}

func (sc *RC4TokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, source)
	return dest, nil
}

func (sc *RC4TokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(dest, source)
	return dest, nil
}

type SHA256RC4TokenSecureFormatter struct {
	key    []byte
	cipher *rc4.Cipher
}

func NewSHA256RC4TokenSecurityProvider(key []byte) *SHA256RC4TokenSecureFormatter {
	var sc = &SHA256RC4TokenSecureFormatter{key: key}
	return sc
}

func (sc *SHA256RC4TokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(source)
	hash := hasher.Sum(nil)
	newSource := append(hash, source...)
	dest := make([]byte, len(newSource))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, newSource)
	return dest, nil
}

func (sc *SHA256RC4TokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	if len(source) < 32 {
		return nil, errors.New("Invalid token")
	}
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, source)
	hasher := sha256.New()
	hasher.Write(dest[32:])
	hash := hasher.Sum(nil)
	for i, b := range hash {
		if b != dest[i] {
			return nil, errors.New("Invalid token")
		}
	}
	return dest[32:], nil
}

type AES128GCMTokenSecureFormatter struct {
	key []byte
}

func NewAES128GCMTokenSecurityProvider(key []byte) *AES128GCMTokenSecureFormatter {
	if len(key) != 16 {
		panic("AES128 key must be exactly 16 bytes long")
	}
	var sc = &AES128GCMTokenSecureFormatter{key: key}
	return sc
}

func (sc *AES128GCMTokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(source)
	hash := hasher.Sum(nil)
	newSource := append(hash, source...)

	aes, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, newSource, nil), nil
}

func (sc *AES128GCMTokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	aes, err := aes.NewCipher(sc.key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := source[:nonceSize], source[nonceSize:]
	dest, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	// hash check
	hasher := sha256.New()
	hasher.Write(dest[32:])
	hash := hasher.Sum(nil)
	for i, b := range hash {
		if b != dest[i] {
			return nil, errors.New("Invalid token")
		}
	}
	return dest[32:], nil
}

type AES256GCMTokenSecureFormatter struct {
	key []byte
}

func NewAES256GCMTokenSecurityProvider(key []byte) *AES256GCMTokenSecureFormatter {
	if len(key) != 32 {
		panic("AES256 key must be exactly 32 bytes long")
	}
	var sc = &AES256GCMTokenSecureFormatter{key: key}
	return sc
}

func (sc *AES256GCMTokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(source)
	hash := hasher.Sum(nil)
	newSource := append(hash, source...)

	aes, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, newSource, nil), nil
}

func (sc *AES256GCMTokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	aes, err := aes.NewCipher(sc.key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := source[:nonceSize], source[nonceSize:]
	dest, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	// hash check
	hasher := sha256.New()
	hasher.Write(dest[32:])
	hash := hasher.Sum(nil)
	for i, b := range hash {
		if b != dest[i] {
			return nil, errors.New("Invalid token")
		}
	}
	return dest[32:], nil
}

type RSATokenSecureFormatter struct {
	key *rsa.PrivateKey
}

func NewRSATokenSecurityProvider(key *rsa.PrivateKey) *RSATokenSecureFormatter {
	var sc = &RSATokenSecureFormatter{key: key}
	return sc
}

func (sc *RSATokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &sc.key.PublicKey, source, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (sc *RSATokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, sc.key, source, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

type JWTHS256TokenSecureFormatter struct {
	key []byte
}

func NewJWTHS256TokenSecurityProvider(key []byte) *JWTHS256TokenSecureFormatter {
	var sc = &JWTHS256TokenSecureFormatter{key: key}
	return sc
}

func (sc *JWTHS256TokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	header := []byte(`{"alg": "HS256", "typ": "JWT"}`)
	b64header := base64.URLEncoding.EncodeToString(header)
	b64payload := base64.URLEncoding.EncodeToString(source)
	jwt := []byte(b64header + "." + b64payload)
	hasher := hmac.New(sha256.New, sc.key)
	hasher.Write(jwt)
	jwt = append(jwt, '.')
	jwt = append(jwt, hasher.Sum(nil)...)
	return jwt, nil
}

func (sc *JWTHS256TokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	jwt := string(source)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("Invalid token")
	}
	b64header := parts[0]
	b64payload := parts[1]
	signature := []byte(parts[2])

	hasher := hmac.New(sha256.New, sc.key)
	hasher.Write([]byte(b64header + "." + b64payload))
	// verify signature
	if !hmac.Equal(signature, hasher.Sum(nil)) {
		return nil, errors.New("Invalid token")
	}
	payload, err := base64.URLEncoding.DecodeString(b64payload)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

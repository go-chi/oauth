package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

var _sutRC4, _sutSHA256, _sutAES128GCM, _sutAES256GCM, _sutJWTHS256 *TokenProvider

func init() {
	_sutRC4 = NewTokenProvider(NewRC4TokenSecurityProvider([]byte("testkey")))
	_sutSHA256 = NewTokenProvider(NewSHA256RC4TokenSecurityProvider([]byte("testkey")))
	_sutAES128GCM = NewTokenProvider(NewAES128GCMTokenSecurityProvider([]byte("testkeytestkey12")))
	_sutAES256GCM = NewTokenProvider(NewAES256GCMTokenSecurityProvider([]byte("testkeytestkeytestkeytestkey1234")))
	_sutJWTHS256 = NewTokenProvider(NewJWTHS256TokenSecurityProvider([]byte("testkey")))
}

func TestCrypt(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutRC4.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecrypt(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutRC4.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutRC4.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptSHA256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptSHA256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutSHA256.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestDecryptSHA256_LongKey(t *testing.T) {
	sutSHA256 := NewTokenProvider(NewSHA256RC4TokenSecurityProvider([]byte("518baffa-b290-4c01-a150-1980f5b06a01")))
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := sutSHA256.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptAES128GCM(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutAES128GCM.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptAES128GCM(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutAES128GCM.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutAES128GCM.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptAES256GCM(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutAES256GCM.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptAES256GCM(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutAES256GCM.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutAES256GCM.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptRSA(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	_sutRSA := NewTokenProvider(NewRSATokenSecurityProvider(key))
	result, err := _sutRSA.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptRSA(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	_sutRSA := NewTokenProvider(NewRSATokenSecurityProvider(key))
	result, err := _sutRSA.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutRSA.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptJWTHS256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutJWTHS256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptJWTHS256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutJWTHS256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutJWTHS256.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func BenchmarkRC4(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	for i := 0; i < b.N; i++ {
		result, _ := _sutRC4.crypt([]byte(token))
		_sutRC4.decrypt(result)
	}
}

func BenchmarkSHA256(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	for i := 0; i < b.N; i++ {
		result, _ := _sutSHA256.crypt([]byte(token))
		_sutSHA256.decrypt(result)
	}
}

func BenchmarkAES128GCM(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	for i := 0; i < b.N; i++ {
		result, _ := _sutAES128GCM.crypt([]byte(token))
		_sutAES128GCM.decrypt(result)
	}
}

func BenchmarkAES256GCM(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	for i := 0; i < b.N; i++ {
		result, _ := _sutAES256GCM.crypt([]byte(token))
		_sutAES256GCM.decrypt(result)
	}
}

func BenchmarkRSA(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("Error %s", err.Error())
	}
	_sutRSA := NewTokenProvider(NewRSATokenSecurityProvider(key))
	for i := 0; i < b.N; i++ {
		result, _ := _sutRSA.crypt([]byte(token))
		_sutRSA.decrypt(result)
	}
}

func BenchmarkJWTHS256(b *testing.B) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	for i := 0; i < b.N; i++ {
		result, _ := _sutJWTHS256.crypt([]byte(token))
		_sutJWTHS256.decrypt(result)
	}
}
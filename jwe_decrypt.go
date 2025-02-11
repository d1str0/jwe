package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

var (
	ErrMissingEncHeader = errors.New("missing \"enc\" header")
	ErrMissingAlgHeader = errors.New("missing \"alg\" header")
)

// Decrypt decrypts JWE ciphertext with the key
func (jwe jwe) Decrypt(key interface{}) ([]byte, error) {

	method := jwe.Header.Enc
	if len(method) == 0 {
		return nil, ErrMissingEncHeader
	}
	cipher, err := getCipher(method)
	if err != nil {
		return nil, err
	}

	alg := jwe.Header.Alg
	if len(alg) == 0 {
		return nil, ErrMissingAlgHeader
	}
	decrypter, err := createDecrypter(key)
	if err != nil {
		return nil, err
	}
	// Decrypt JWE Encrypted Key with the recipient's private key to produce CEK.
	cek, err := decrypter.Decrypt(jwe.RecipientKey, alg)
	if err != nil {
		return nil, err
	}

	// Serialize Authenticated Data
	rawProtected, err := json.Marshal(jwe.Header)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	// Perform authenticated decryption on the ciphertext
	data, err := cipher.decrypt(cek, []byte(rawProtectedBase64), jwe.IV, jwe.Ciphertext, jwe.Tag)

	return data, err
}

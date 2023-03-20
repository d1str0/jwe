package jwe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// NewJWE creates a new JWE token.
// The plaintext will be encrypted with the method using a Content Encryption Key (cek).
// The cek will be encrypted with the alg using the key.
func NewJWE(alg KeyAlgorithm, key interface{}, method EncryptionType, plaintext []byte) (*jwe, error) {
	jwe := &jwe{}

	jwe.Header.Enc = method
	chipher, err := getCipher(method)
	if err != nil {
		return nil, err
	}

	// Generate a random Content Encryption Key (CEK).
	cek, err := generateKey(chipher.keySize)
	if err != nil {
		return nil, err
	}

	// Encrypt the CEK with the recipient's public key to produce the JWE Encrypted Key.
	jwe.Header.Alg = alg
	encrypter, err := createEncrypter(key)
	if err != nil {
		return nil, err
	}
	jwe.RecipientKey, err = encrypter.Encrypt(cek, alg)
	if err != nil {
		return nil, err
	}

	// Serialize Authenticated Data
	rawProtected, err := json.Marshal(jwe.Header)
	if err != nil {
		return nil, err
	}
	rawProtectedBase64 := base64.RawURLEncoding.EncodeToString(rawProtected)

	// Perform authenticated encryption on the plaintext
	jwe.IV, jwe.Ciphertext, jwe.Tag, err = chipher.encrypt(cek, []byte(rawProtectedBase64), plaintext)
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

// jwe internal structure represents JWE in unmarshalling format.
type jwe struct {
	// protected fields: alg - algorithm to encrypt a key and enc - algorithm to encrypt text.
	Header struct {
		Alg KeyAlgorithm   `json:"alg,omitempty"`
		Enc EncryptionType `json:"enc,omitempty"`
	} `json:"header"`

	// recipientKey field is the key encrypted.
	RecipientKey []byte `json:"encrypted_key"`

	// iv field is initialization vector.
	IV []byte `json:"iv"`

	// ciphertext filed is text encrypted by the enc with the key.
	Ciphertext []byte `json:"ciphertext"`

	// tag field is authentication tag.
	Tag []byte `json:"tag"`
}

// CompactSerialize serialize JWE to compact form.
// https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
func (jwe *jwe) CompactSerialize() (string, error) {
	rawProtected, err := json.Marshal(jwe.Header)
	if err != nil {
		return "", err
	}

	protected := base64.RawURLEncoding.EncodeToString(rawProtected)
	encryptedKey := base64.RawURLEncoding.EncodeToString(jwe.RecipientKey)
	iv := base64.RawURLEncoding.EncodeToString(jwe.IV)
	ciphertext := base64.RawURLEncoding.EncodeToString(jwe.Ciphertext)
	tag := base64.RawURLEncoding.EncodeToString(jwe.Tag)

	return strings.Join([]string{protected, encryptedKey, iv, ciphertext, tag}, "."), nil
}

package jwe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func ParseEncrypted(input string) (*jwe, error) {

	if strings.HasPrefix(input, "{") {
		return parseEncrypted(input)
	}

	return parseEncryptedCompact(input)
}

func parseEncrypted(input string) (*jwe, error) {

	encrypted := &jwe{}
	err := json.Unmarshal([]byte(input), encrypted)
	if err != nil {
		return nil, errors.New("unable to parse JSON input")
	}
	return encrypted, nil
}

func parseEncryptedCompact(input string) (*jwe, error) {
	parts := strings.Split(input, ".")

	if len(parts) != 5 {
		return nil, errors.New("encrypted token contains an invalid number of segments")
	}

	jwe := &jwe{}

	rawProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	if len(rawProtected) == 0 {
		return nil, errors.New("protected headers are empty")
	}

	err = json.Unmarshal(rawProtected, &jwe.Header)
	if err != nil {
		return nil, errors.New("protected headers are not in JSON format")
	}

	jwe.RecipientKey, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	jwe.IV, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwe.Ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	jwe.Tag, err = base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

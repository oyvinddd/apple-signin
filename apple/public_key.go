package apple

import (
	"encoding/json"
	"net/http"
)

type (
	JWKSet struct {
		Keys []JWKSetKey `json:"keys"`
	}

	JWKSetKey struct {
		Alg string `json:"alg"`

		E string `json:"e"`

		Kid string `json:"kid"`

		Kty string `json:"kty"`

		N string `json:"n"`

		Use string `json:"use"`
	}
)

// https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature
func getApplePublicKey() (JWKSet, error) {
	res, err := http.Get(applePublicKeyURL)
	if err != nil {
		return JWKSet{}, err
	}

	var jwk JWKSet
	if err = json.NewDecoder(res.Body).Decode(&jwk); err != nil {
		return JWKSet{}, err
	}

	return jwk, nil
}

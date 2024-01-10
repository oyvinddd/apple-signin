package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	// Fetch Apple’s public key to verify the ID token signature.
	applePublicKeyURL string = "https://appleid.apple.com/auth/keys"

	// Validate an authorization grant code delivered to your app to obtain tokens, or validate an existing refresh token.
	appleTokenURL string = "https://appleid.apple.com/auth/token"
)

const (
	GrantTypeAuthorizationCode AppleGrantType = "authorization_code"

	GrantTypeRefreshToken AppleGrantType = "refresh_token"
)

const (

	// ErrorTypeInvalidRequest The request is malformed, typically because it’s missing a parameter,
	//contains an unsupported parameter, includes multiple credentials, or uses more than one
	// mechanism for authenticating the client.
	ErrorTypeInvalidRequest AppleErrorType = "invalid_request"

	ErrorTypeInvalidClient AppleErrorType = "invalid_client"

	ErrorTypeInvalidGrant AppleErrorType = "invalid_grant"

	ErrorTypeUnauthorizedClient AppleErrorType = "unauthorized_client"

	ErrorTypeUnsupportedGrant AppleErrorType = "unsupported_grant_type"

	ErrorTypeInvalidScope AppleErrorType = "invalid_scope"

	ErrorTypeInternalServerError AppleErrorType = "server_error"
)

type (
	AppleClient struct {
		ClientID string

		ClientSecret string
	}

	AppleTokenResponse struct {

		// A token used to access allowed data, such as generating and exchanging transfer identifiers during user migration.
		AccessToken string `json:"access_token"`

		// The amount of time, in seconds, before the access token expires.
		ExpiresIn int `json:"expires_in"`

		// A JSON Web Token (JWT) that contains the user’s identity information.
		IdToken string `json:"id_token"`

		// The refresh token used to regenerate new access tokens when validating an authorization code.
		// Store this token securely on your server. The refresh token isn’t returned when validating
		// an existing refresh token.
		RefreshToken string `json:"refresh_token"`

		// The type of access token, which is always bearer.
		TokenType string `json:"token_type"`
	}

	AppleErrorResponse struct {

		// A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
		AppleError AppleErrorType `json:"error"`
	}

	AppleErrorType string

	AppleGrantType string
)

func main() {
	fmt.Println("hello Go!")
	_ = NewAppleClient("", "")
}

func NewAppleClient(clientID, clientSecret string) *AppleClient {
	return &AppleClient{ClientID: clientID, ClientSecret: clientSecret}
}

// https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature
func getApplePublicKey() error {
	_, err := http.Get(applePublicKeyURL)
	return err
}

func (client AppleClient) validateAuthorizationCode(code string) error {
	body := urlEncodedValidationRequestBody(client.ClientID, client.ClientSecret, code)
	// body needs to be form-data with Content-Type: application/x-www-form-urlencoded
	_, err := http.Post(appleTokenURL, "application/x-www-form-urlencoded", strings.NewReader(body))

	return err
}

func (client AppleClient) validateRefreshToken(token string) (AppleTokenResponse, error) {
	body := urlEncodedValidationRequestBody(client.ClientID, client.ClientSecret, token)
	res, err := http.Post(appleTokenURL, "application/x-www-form-urlencoded", strings.NewReader(body))

	if res.StatusCode == http.StatusBadRequest {
		var appleError AppleErrorResponse
		if err = json.NewDecoder(res.Body).Decode(&appleError); err != nil {
			return AppleTokenResponse{}, err
		}
		return AppleTokenResponse{}, appleError
	}

	// no predefined error message from POST request to Apple, but we still got an error so just return a general error
	if err != nil {
		return AppleTokenResponse{}, AppleErrorResponse{ErrorTypeInternalServerError}
	}

	var tokenResponse AppleTokenResponse
	if err = json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		return AppleTokenResponse{}, err
	}

	return tokenResponse, nil
}

func urlEncodedValidationRequestBody(clientID, clientSecret, authorizationCode string) string {
	body := url.Values{}
	body.Add("client_id", clientID)
	body.Add("client_secret", clientSecret)
	body.Add("code", authorizationCode)
	body.Add("grant_type", string(GrantTypeAuthorizationCode))
	// body.Add("redirect_uri", "") unsure if we need this for apps
	return body.Encode()
}

func urlEncodedRefreshTokenRequestBody(clientID, clientSecret, refreshToken string) string {
	body := url.Values{}
	body.Add("client_id", clientID)
	body.Add("client_secret", clientSecret)
	body.Add("refresh_token", refreshToken)
	body.Add("grant_type", string(GrantTypeRefreshToken))
	return body.Encode()
}

// AppleError error interface conformance

func (response AppleErrorResponse) Error() string {
	return string(response.AppleError)
}

package apple

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

const (
	// Fetch Apple’s public key to verify the ID token signature.
	applePublicKeyURL string = "https://appleid.apple.com/auth/keys"

	// Validate an authorization grant code delivered to your app to obtain tokens, or validate
	// an existing refresh token.
	appleTokenURL string = "https://appleid.apple.com/auth/token"

	// Invalidate the tokens and associated user authorizations for a user when they are no longer
	// associated with your app.
	appleRevokeURL string = "https://appleid.apple.com/auth/revoke"
)

type (
	Client struct {
		config Config
	}

	Config struct {
		ClientID string

		ClientSecret string
	}
)

func NewClient(clientID, clientSecret string) *Client {
	return &Client{config: Config{ClientID: clientID, ClientSecret: clientSecret}}
}

func (client Client) validateAuthorizationCode(code string) error {
	body := urlEncodedFormValidationRequestBody(client.config.ClientID, client.config.ClientID, code)
	// body needs to be form-data with Content-Type: application/x-www-form-urlencoded
	_, err := http.Post(appleTokenURL, "application/x-www-form-urlencoded", strings.NewReader(body))

	return err
}

func (client Client) validateRefreshToken(token string) (TokenResponse, error) {
	body := urlEncodedFormValidationRequestBody(client.config.ClientID, client.config.ClientSecret, token)
	res, err := http.Post(appleTokenURL, "application/x-www-form-urlencoded", strings.NewReader(body))

	if res.StatusCode == http.StatusBadRequest {
		var appleError ErrorResponse
		if err = json.NewDecoder(res.Body).Decode(&appleError); err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, appleError
	}

	// no predefined error message from POST request to Apple, but we still got an error so just return a general error
	if err != nil {
		return TokenResponse{}, ErrorResponse{ErrorTypeInternalServerError}
	}

	var tokenResponse TokenResponse
	if err = json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

func (client Client) RevokeToken() {

	res, err := http.Post(appleRevokeURL, "application/x-www-form-urlencoded")
}

func urlEncodedFormValidationRequestBody(clientID, clientSecret, authorizationCode string) string {
	body := url.Values{}
	body.Add("client_id", clientID)
	body.Add("client_secret", clientSecret)
	body.Add("code", authorizationCode)
	body.Add("grant_type", string(GrantTypeAuthorizationCode))
	// body.Add("redirect_uri", "") unsure if we need this for apps
	return body.Encode()
}

func urlEncodedFormRefreshTokenRequestBody(clientID, clientSecret, refreshToken string) string {
	body := url.Values{}
	body.Add("client_id", clientID)
	body.Add("client_secret", clientSecret)
	body.Add("refresh_token", refreshToken)
	body.Add("grant_type", string(GrantTypeRefreshToken))
	return body.Encode()
}

func urlEncodedFormRevokeRequestBody(clientID, clientSecret, token string, tokenType TokenType) string {
	body := url.Values{}
	body.Add("client_id", clientID)
	body.Add("client_secret", clientSecret)
	body.Add("token", token)
	body.Add("token_type_hint", string(tokenType))
	return body.Encode()
}

// AppleError error interface conformance

func (response ErrorResponse) Error() string {
	return string(response.AppleError)
}

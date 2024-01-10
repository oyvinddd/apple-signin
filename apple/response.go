package apple

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"

	GrantTypeRefreshToken GrantType = "refresh_token"
)

const (
	TokenTypeAccessToken TokenType = "access_token"

	TokenTypeRefreshToken TokenType = "refresh_token"
)

const (

	// ErrorTypeInvalidRequest The request is malformed, typically because it’s missing a parameter,
	//contains an unsupported parameter, includes multiple credentials, or uses more than one
	// mechanism for authenticating the client.
	ErrorTypeInvalidRequest ErrorType = "invalid_request"

	ErrorTypeInvalidClient ErrorType = "invalid_client"

	ErrorTypeInvalidGrant ErrorType = "invalid_grant"

	ErrorTypeUnauthorizedClient ErrorType = "unauthorized_client"

	ErrorTypeUnsupportedGrant ErrorType = "unsupported_grant_type"

	ErrorTypeInvalidScope ErrorType = "invalid_scope"

	ErrorTypeInternalServerError ErrorType = "server_error"
)

type (
	TokenResponse struct {

		// A token used to access allowed data, such as generating and exchanging transfer
		// identifiers during user migration.
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

	ErrorResponse struct {

		// A string that describes the reason for the unsuccessful request. The string consists
		// of a single allowed value.
		AppleError ErrorType `json:"error"`
	}

	ErrorType string

	GrantType string

	TokenType string
)

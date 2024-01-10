package apple

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// TODO: load private key from file and then sign the jwt token using this key
func CreateClientSecret(appleTeamID, appleClientID string) *jwt.Token {

	// ninety days in seconds
	ninetyDays := time.Minute * 60 * 24 * 90

	start := time.Now().Second()
	expiration := time.Now().Add(ninetyDays).Second()

	claims := jwt.MapClaims{
		// The issuer registered claim identifies the principal that issued the client secret. Because the client
		// secret belongs to your developer team, use the 10-character Team ID associated with your developer account.
		"iss": appleTeamID, // 10-character team ID from Apple

		// The issued at registered claim indicates the time at which you generated the client secret, in terms of the
		// number of seconds following the epoch (January 1st 1970 00:00:00), in UTC.
		"iat": start, // current time in seconds

		// The expiration time registered claim identifies the time on or after which the client secret expires.
		// It’s an error to request an expiration time more than 15777000 seconds (six months) in the future,
		// as measured by the clock on Apple’s servers.
		"exp": expiration,

		// The audience registered claim identifies the intended recipient of the client secret. Because the client
		// secret is sent to the validation server, use https://appleid.apple.com as the audience.
		"aud": "https://appleid.apple.com",

		// The subject registered claim identifies the principal that is the subject of the client secret. Because
		// this client secret is meant for your app, use the same App ID or Services ID that you use as the client_id
		// to generate and refresh tokens. The value is case-sensitive.
		"sub": appleClientID,
	}

	return jwt.NewWithClaims(jwt.SigningMethodES256, claims)
}

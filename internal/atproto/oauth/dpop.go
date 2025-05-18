package oauth

import (
	"time"

	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/token"
)

// https://datatracker.ietf.org/doc/html/rfc9449
func makeDPoPProof(method, url string, pkey []byte, nonce string) (string, error) {
	type claims struct {
		Jti   string `json:"jti"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
		Htm   string `json:"htm"`
		Htu   string `json:"htu"`
		Nonce string `json:"nonce"`
	}

	now := time.Now()

	d := claims{
		Jti:   token.GenRandomString(32, token.AlphaNumCharset),
		Htm:   method,
		Htu:   url,
		Iat:   now.Unix(),
		Exp:   now.Add(30 * time.Second).Unix(),
		Nonce: nonce,
	}

	return token.SignDPoPToken(d, pkey)
}

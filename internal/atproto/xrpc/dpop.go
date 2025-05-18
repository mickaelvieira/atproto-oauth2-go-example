package xrpc

import (
	"time"

	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/token"
)

// https://datatracker.ietf.org/doc/html/rfc9449
func makeDPoPProof(method, uri, tkn, issuer, nonce string, pkey []byte) (string, error) {
	type claims struct {
		Jti   string `json:"jti"`
		Iss   string `json:"iss"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
		Htm   string `json:"htm"`
		Htu   string `json:"htu"`
		Ath   string `json:"ath"`
		Nonce string `json:"nonce"`
	}

	now := time.Now()

	d := claims{
		Iss:   issuer,
		Jti:   token.GenRandomString(32, token.AlphaNumCharset),
		Ath:   token.CodeChallenge(tkn),
		Htm:   method,
		Htu:   uri,
		Iat:   now.Unix(),
		Exp:   now.Add(60 * time.Second).Unix(),
		Nonce: nonce,
	}

	return token.SignDPoPToken(d, pkey)
}

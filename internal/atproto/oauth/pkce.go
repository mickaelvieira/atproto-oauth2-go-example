package oauth

import "github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/token"

const (
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	PKCELen     = 64
	PKCECharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)

type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

func newPKCE() PKCE {
	v := token.GenRandomString(PKCELen, PKCECharset)

	return PKCE{
		Verifier:  v,
		Challenge: token.CodeChallenge(v),
		Method:    "S256",
	}
}

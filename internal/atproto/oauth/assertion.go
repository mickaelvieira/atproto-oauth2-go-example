package oauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/token"
)

func makeAssertion(pkey jose.JSONWebKey, issuer string, clientID string) (string, error) {
	type claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
		Jti string `json:"jti"`
	}

	key := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       pkey.Key,
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader("kid", pkey.KeyID)
	opts.WithType("JWT")

	signer, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create assertion signer: %v", err)
	}

	now := time.Now()
	d := claims{
		Iss: clientID,
		Sub: clientID,
		Aud: issuer,
		Exp: now.Add(5 * time.Minute).Unix(),
		Iat: now.Unix(),
		Jti: token.GenRandomString(32, token.AlphaNumCharset),
	}

	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	sig, err := signer.Sign(b)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	token, err := sig.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %v", err)
	}

	return token, nil
}

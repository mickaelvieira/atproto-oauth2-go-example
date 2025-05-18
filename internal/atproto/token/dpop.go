package token

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

func DPoPSigner(pkey []byte) (jose.Signer, error) {
	var priv jose.JSONWebKey

	if err := json.Unmarshal(pkey, &priv); err != nil {
		return nil, err
	}

	pub := priv.Public()
	data := make(map[string]any)

	b, err := pub.MarshalJSON()
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	key := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       priv.Key,
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "dpop+jwt")
	opts.WithHeader("jwk", data)

	return jose.NewSigner(key, opts)
}

func SignDPoPToken(t any, pkey []byte) (string, error) {
	signer, err := DPoPSigner(pkey)
	if err != nil {
		return "", fmt.Errorf("failed to create dpop signer: %v", err)
	}

	j, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	s, err := signer.Sign(j)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return s.CompactSerialize()
}

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/go-jose/go-jose/v4"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/database"
	"github.com/potproject/atproto-oauth2-go-example/key"
)

func getClientMetadata(host string) clientMetadata {
	return clientMetadata{
		ClientName:                  "Demo ATProto OAuth Example",
		ClientURI:                   "https://" + host,
		ClientID:                    "https://" + host + "/oauth/client-metadata",
		ApplicationType:             "web",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		Scope:                       "atproto transition:generic",
		ResponseTypes:               []string{"code"},
		RedirectURIs:                []string{"https://" + host + "/oauth/callback"},
		DPopBoundAccessTokens:       true,
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		JwksUri:                     "https://" + host + "/oauth/jwks",
	}
}

// @see https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata
type clientMetadata struct {
	ClientName                  string   `json:"client_name,omitempty"`                     // optional
	ClientURI                   string   `json:"client_uri,omitempty"`                      // optional
	ClientID                    string   `json:"client_id"`                                 // required
	ApplicationType             string   `json:"application_type,omitempty"`                // optional
	GrantTypes                  []string `json:"grant_types"`                               // required
	Scope                       string   `json:"scope"`                                     // required
	ResponseTypes               []string `json:"response_types"`                            // required
	RedirectURIs                []string `json:"redirect_uris"`                             // required
	DPopBoundAccessTokens       bool     `json:"dpop_bound_access_tokens"`                  // required
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`      // optional
	TokenEndpointAuthSigningAlg string   `json:"token_endpoint_auth_signing_alg,omitempty"` // optional
	JwksUri                     string   `json:"jwks_uri,omitempty"`                        // optional
	Jwks                        string   `json:"jwks,omitempty"`                            // optional
	LogoURI                     string   `json:"logo_uri,omitempty"`                        // optional
	TosURI                      string   `json:"tos_uri,omitempty"`                         // optional
	PolicyURI                   string   `json:"policy_uri,omitempty"`                      // optional
}

type Service interface {
	ClientID() string
	RedirectURI() string
	Metadata() clientMetadata
	PrivateKey() jose.JSONWebKey
	PushAuthorizationRequest(ctx context.Context, ident *identity.Identity, server AuthServerMetadata) (*parResponse, *FlowData, error)
	RequestAccessToken(ctx context.Context, params callbackParams) (*accessTokenResponse, *FlowData, error)
	RefreshAccessToken(ctx context.Context, session *database.OAuthSession) (*refreshTokenResponse, error)
}

type Client struct {
	metadata clientMetadata
	secret   []byte
	pkey     *jose.JSONWebKey
	http     *http.Client
	storage  Storage
}

type Option func(c *Client)

func WithStorage(storage Storage) Option {
	return func(c *Client) {
		c.storage = storage
	}
}

func WithClient(client *http.Client) Option {
	return func(c *Client) {
		c.http = client
	}
}

func NewClient(host, secret string, opts ...Option) Service {
	c := &Client{
		secret:   []byte(secret),
		metadata: getClientMetadata(host),
		storage:  defaultStorage(),
		http:     &http.Client{Timeout: time.Second * 60},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) ClientID() string {
	return c.metadata.ClientID
}

func (c *Client) RedirectURI() string {
	return c.metadata.RedirectURIs[0]
}

func (c *Client) Metadata() clientMetadata {
	return c.metadata
}

func (c *Client) PrivateKey() jose.JSONWebKey {
	var key jose.JSONWebKey
	if err := json.Unmarshal(c.secret, &key); err != nil {
		panic(err)
	}
	return key
}

func (c *Client) PushAuthorizationRequest(ctx context.Context, ident *identity.Identity, server AuthServerMetadata) (*parResponse, *FlowData, error) {
	flow := newFlowData(ident, server)

	assert, err := makeAssertion(c.PrivateKey(), flow.Issuer, c.ClientID())
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedAssertion, err)
	}

	dpopPrivateJWK := []byte(key.GenerateSecretJWK())
	dpopWithoutNonce, err := makeDPoPProof(http.MethodPost, flow.PAREndpoint, dpopPrivateJWK, "")
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
	}

	res, dpopNonce, err := c.pushAuthorizationRequest(ctx, flow, dpopWithoutNonce, assert)
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedPARRequest, err)
	}

	// server requires the service to resend the request with the provided nonce
	if dpopNonce != "" {
		dpopWithNonce, err := makeDPoPProof(http.MethodPost, flow.PAREndpoint, dpopPrivateJWK, dpopNonce)
		if err != nil {
			return nil, flow, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
		}

		res, _, err = c.pushAuthorizationRequest(ctx, flow, dpopWithNonce, assert)
		if err != nil {
			return nil, flow, fmt.Errorf("%s: %v", MsgFailedPARRequest, err)
		}
	}

	flow.Nonce = dpopNonce
	flow.DPoPPrivateJWK = dpopPrivateJWK

	flow = c.storage.Set(flow)

	return &res, flow, nil
}

func (c *Client) pushAuthorizationRequest(ctx context.Context, flow *FlowData, dpop, assert string) (parResponse, string, error) {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
	// https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
	// https://datatracker.ietf.org/doc/html/rfc7521#section-4.2
	v := url.Values{}
	v.Set("state", flow.State)
	v.Set("scope", c.metadata.Scope)
	v.Set("client_id", c.ClientID())
	v.Set("redirect_uri", c.RedirectURI())
	v.Set("response_type", "code")
	v.Set("code_challenge", flow.PKSE.Challenge)
	v.Set("code_challenge_method", flow.PKSE.Method)
	v.Set("client_assertion", assert)
	v.Set("client_assertion_type", AssertionType)
	v.Set("login_hint", flow.Handle)

	var par parResponse

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		flow.PAREndpoint,
		strings.NewReader(v.Encode()),
	)

	if err != nil {
		return par, "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(DPoPHeader, dpop)

	r, err := c.http.Do(req)
	if err != nil {
		return par, "", err
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return par, "", err
	}

	if r.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(b, &par); err != nil {
			return par, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
		}
		return par, "", nil
	}

	var oauthError ErrorResponse
	if err := json.Unmarshal(b, &oauthError); err != nil {
		return par, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
	}

	if r.StatusCode == http.StatusBadRequest && oauthError.Code == OAuthNonceErrorCode {
		return par, r.Header.Get(NonceHeader), nil
	}

	return par, "", fmt.Errorf("status %d, error %w", r.StatusCode, oauthError)
}

func (c *Client) RequestAccessToken(ctx context.Context, p callbackParams) (*accessTokenResponse, *FlowData, error) {
	flow := c.storage.Get(p.State)
	if flow == nil {
		return nil, flow, fmt.Errorf("failed to retrieve state %s", p.State)
	}

	assert, err := makeAssertion(c.PrivateKey(), flow.Issuer, c.ClientID())
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedAssertion, err)
	}

	dpop, err := makeDPoPProof(http.MethodPost, flow.TokenEndpoint, flow.DPoPPrivateJWK, flow.Nonce)
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
	}

	res, nonce, err := c.requestAccessToken(ctx, p, flow, dpop, assert)
	if err != nil {
		return nil, flow, fmt.Errorf("%s: %v", MsgFailedTokensRequest, err)
	}

	if nonce != "" {
		dpop, err := makeDPoPProof(http.MethodPost, flow.TokenEndpoint, flow.DPoPPrivateJWK, nonce)
		if err != nil {
			return nil, flow, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
		}

		res, _, err = c.requestAccessToken(ctx, p, flow, dpop, assert)
		if err != nil {
			return nil, flow, fmt.Errorf("%s: %v", MsgFailedTokensRequest, err)
		}
	}

	if res.DID != flow.DID {
		return nil, flow, fmt.Errorf("DIDs should match, expected %s, got %s", flow.DID, res.DID)
	}

	if ok := c.storage.Unset(flow.State); !ok {
		return nil, flow, fmt.Errorf("failed to remove object stored with id %s", flow.State)
	}

	return &res, flow, nil
}

func (c *Client) requestAccessToken(ctx context.Context, p callbackParams, flow *FlowData, dpop string, assert string) (accessTokenResponse, string, error) {
	v := url.Values{}
	v.Set("code", p.Code)
	v.Set("client_id", c.ClientID())
	v.Set("grant_type", "authorization_code")
	v.Set("redirect_uri", c.RedirectURI())
	v.Set("code_verifier", flow.PKSE.Verifier)
	v.Set("client_assertion", assert)
	v.Set("client_assertion_type", AssertionType)

	var token accessTokenResponse

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		flow.TokenEndpoint,
		strings.NewReader(v.Encode()),
	)

	if err != nil {
		return token, "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(DPoPHeader, dpop)

	r, err := c.http.Do(req)
	if err != nil {
		return token, "", err
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return token, "", err
	}

	if r.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b, &token); err != nil {
			return token, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
		}
		return token, "", nil
	}

	var oauthError ErrorResponse
	if err := json.Unmarshal(b, &oauthError); err != nil {
		return token, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
	}

	if r.StatusCode == http.StatusBadRequest {
		if oauthError.Code == OAuthNonceErrorCode {
			return token, r.Header.Get(NonceHeader), nil
		}
	}

	return token, "", fmt.Errorf("status %d, error %w", r.StatusCode, oauthError)
}

func (c *Client) RefreshAccessToken(ctx context.Context, s *database.OAuthSession) (*refreshTokenResponse, error) {
	metadata, err := FetchAuthServerMetadata(s.AuthServer)
	if err != nil {
		return nil, err
	}

	assert, err := makeAssertion(c.PrivateKey(), s.AuthServer, c.ClientID())
	if err != nil {
		return nil, fmt.Errorf("%s: %v", MsgFailedAssertion, err)
	}

	dpop, err := makeDPoPProof(http.MethodPost, metadata.TokenEndpoint, s.PrivateKey, s.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
	}

	res, nonce, err := c.refreshAccessToken(ctx, s, metadata, dpop, assert)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", MsgFailedTokensRequest, err)
	}

	if nonce != "" {
		dpop, err := makeDPoPProof(http.MethodPost, metadata.TokenEndpoint, s.PrivateKey, nonce)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", MsgFailedDPoP, err)
		}

		res, _, err = c.refreshAccessToken(ctx, s, metadata, dpop, assert)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", MsgFailedTokensRequest, err)
		}
	}

	return &refreshTokenResponse{accessTokenResponse: res, Nonce: nonce}, nil
}

func (c *Client) refreshAccessToken(ctx context.Context, s *database.OAuthSession, d AuthServerMetadata, dpop string, assert string) (accessTokenResponse, string, error) {
	v := url.Values{}
	v.Set("client_id", c.ClientID())
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", s.RefreshToken)
	v.Set("client_assertion", assert)
	v.Set("client_assertion_type", AssertionType)

	var token accessTokenResponse

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		d.TokenEndpoint,
		strings.NewReader(v.Encode()),
	)

	if err != nil {
		return token, "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(DPoPHeader, dpop)

	r, err := c.http.Do(req)
	if err != nil {
		return token, "", err
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return token, "", err
	}

	if r.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b, &token); err != nil {
			return token, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
		}
		return token, "", nil
	}

	var oauthError ErrorResponse
	if err := json.Unmarshal(b, &oauthError); err != nil {
		return token, "", fmt.Errorf("%s: %v", MsgFailedParsing, err)
	}

	if r.StatusCode == http.StatusBadRequest {
		if oauthError.Code == OAuthNonceErrorCode {
			return token, r.Header.Get(NonceHeader), nil
		}
	}

	return token, "", fmt.Errorf("status %d, error %w", r.StatusCode, oauthError)
}

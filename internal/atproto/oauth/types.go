package oauth

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

const (
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// https://datatracker.ietf.org/doc/html/rfc9449#section-8
	DPoPHeader          = "DPoP"
	NonceHeader         = "DPoP-Nonce"
	OAuthNonceErrorCode = "use_dpop_nonce"

	// https://datatracker.ietf.org/doc/html/rfc7521#section-4.1.1
	OAuthInvalidGrantCode = "invalid_grant"

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	OAuthAccessDeniedCode            = "access_denied"
	OAuthInvalidScopeCode            = "invalid_scope"
	OAuthServerErrorCode             = "server_error"
	OAuthInvalidRequestCode          = "invalid_request"
	OAuthUnauthorizedClientCode      = "unauthorized_client"
	OAuthTemporarilyUnavailableCode  = "temporarily_unavailable"
	OAuthUnsupportedTesponseTypeCode = "unsupported_response_type"
)

const (
	MsgFailedDPoP          = "failed to create DPoP proof"
	MsgFailedSecret        = "failed to generate secret key"
	MsgFailedParsing       = "failed to parse response"
	MsgFailedAssertion     = "failed to create client assertion"
	MsgFailedPARRequest    = "OAuth PAR request failed"
	MsgFailedTokensRequest = "OAuth tokens request failed"
)

// https://datatracker.ietf.org/doc/html/rfc9126#section-2.2
type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (n parResponse) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("request_uri", n.RequestURI),
		slog.Int("expires_in", n.ExpiresIn))
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type accessTokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	DID          string `json:"sub"`
}

func (n accessTokenResponse) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("access_token", strings.Repeat("x", len(n.AccessToken))),
		slog.String("refresh_token", strings.Repeat("x", len(n.RefreshToken))),
		slog.String("token_type", n.TokenType),
		slog.String("scope", n.Scope),
		slog.String("did", n.DID),
		slog.Int("expires_in", n.ExpiresIn))
}

type refreshTokenResponse struct {
	accessTokenResponse
	Nonce string
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
type ErrorResponse struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri"`
}

func (e ErrorResponse) Error() string {
	if e.URI != "" {
		return fmt.Sprintf("code: %s, description: %s, uri: %s", e.Code, e.Description, e.URI)
	}
	return fmt.Sprintf("code: %s, description: %s", e.Code, e.Description)
}

type callbackParams struct {
	// issuer domain sending the authorization code
	ISS string `json:"iss"`
	// the authorization code to use to request tokens (access & refresh)
	Code string `json:"code"`
	// the state sent by the service alongside the initialization request
	State string `json:"state"`
}

func (n callbackParams) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("iss", n.ISS),
		slog.String("code", strings.Repeat("x", len(n.Code))),
		slog.String("state", n.State))
}

func ToCallbackParams(v url.Values) callbackParams {
	return callbackParams{
		ISS:   v.Get("iss"),
		Code:  v.Get("code"),
		State: v.Get("state")}
}

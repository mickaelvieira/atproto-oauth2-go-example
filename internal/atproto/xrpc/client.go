package xrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/oauth"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/database"
)

func NewClient(s *database.OAuthSession) *Client {
	return &Client{
		session: s,
		http:    &http.Client{Timeout: time.Second * 120},
	}
}

func makeURLParams(p map[string]any) string {
	if len(p) == 0 {
		return ""
	}

	params := url.Values{}
	for k, v := range p {
		if s, ok := v.([]string); ok {
			for _, v := range s {
				params.Add(k, v)
			}
			continue
		}
		params.Add(k, fmt.Sprint(v))
	}

	return fmt.Sprintf("?%s", params.Encode())
}

func makeBody(d any) io.Reader {
	if d == nil {
		return nil
	}

	if r, ok := d.(io.Reader); ok {
		return r
	}

	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}

	return bytes.NewReader(b)
}

type Client struct {
	session *database.OAuthSession
	http    *http.Client
}

func (c *Client) Query(ctx context.Context, endpoint string, params map[string]any) ([]byte, error) {
	uri := fmt.Sprintf("%s/xrpc/%s%s", c.session.PDSServer, endpoint, makeURLParams(params))
	return c.handle(ctx, http.MethodGet, uri, nil)
}

func (c *Client) Procedure(ctx context.Context, endpoint string, b any) ([]byte, error) {
	uri := fmt.Sprintf("%s/xrpc/%s", c.session.PDSServer, endpoint)
	return c.handle(ctx, http.MethodPost, uri, makeBody(b))
}

func (c *Client) handle(ctx context.Context, mth string, uri string, body io.Reader) ([]byte, error) {
	pky := c.session.PrivateKey
	tkn := c.session.AccessToken

	dpop, err := makeDPoPProof(mth, uri, tkn, c.session.AuthServer, c.session.Nonce, pky)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", oauth.MsgFailedDPoP, err)
	}

	req, err := http.NewRequestWithContext(ctx, mth, uri, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("DPoP %s", tkn))
	req.Header.Set("DPoP", dpop)

	res, nonce, err := c.request(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", oauth.MsgFailedTokensRequest, err)
	}

	if nonce != "" {
		dpop, err := makeDPoPProof(mth, uri, tkn, c.session.AuthServer, nonce, pky)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", oauth.MsgFailedDPoP, err)
		}

		req, err := http.NewRequestWithContext(ctx, mth, uri, body)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", fmt.Sprintf("DPoP %s", tkn))
		req.Header.Set("DPoP", dpop)

		res, _, err = c.request(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", oauth.MsgFailedTokensRequest, err)
		}
	}

	return res, nil
}

func (c *Client) request(req *http.Request) ([]byte, string, error) {
	res, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}

	if res.StatusCode == http.StatusOK {
		return b, "", nil
	}

	var oauthError oauth.ErrorResponse
	if err := json.Unmarshal(b, &oauthError); err != nil {
		return nil, "", fmt.Errorf("%s: %v", oauth.MsgFailedParsing, err)
	}

	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusUnauthorized {
		if oauthError.Code == oauth.OAuthNonceErrorCode {
			return nil, res.Header.Get(oauth.NonceHeader), nil
		}
	}

	return nil, "", fmt.Errorf("status %d, error %w", res.StatusCode, oauthError)
}

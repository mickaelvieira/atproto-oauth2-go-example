# AT Protocol OAuth2 Go Example

This is a example project showing how to implement an Golang web service which uses atproto OAuth for authentication. There is a service running at https://oauth-atproto.demo.mkv.engineering/

[python-oauth-web-app](https://github.com/bluesky-social/cookbook/tree/main/python-oauth-web-app) & [atproto-oauth2-go-example](https://github.com/potproject/atproto-oauth2-go-example) are used as references for the implementation.

## Docs

- [ATProto OAuth Docs](https://atproto.com/specs/oauth)
- [OAuth for AT Protocol](https://docs.bsky.app/blog/oauth-atproto)

## Prerequisites

- Go 1.24 or later
- A domain with HTTPS support (for production use)
- A Bluesky account

## Setup

Clone the repository:
```bash
git clone https://github.com/mickaelvieira/atproto-oauth2-go-example
cd atproto-oauth2-go-example
```

Install dependencies:
```bash
go mod download -x
```

Generate a Secret JWK:
```bash
go run genkey/main.go
```

## Running the Server

Start the server:

```bash
export SECRET_JWK='...' # Export the Secret JWK previously generated
go run main.go -port 9000 -host your-domain.com
```

The server will start on the specified port with the following endpoints:

- `/`: Login page
- `/oauth/login`: Access token requests endpoint
- `/oauth/logout`: logout endpoint
- `/oauth/callback`: OAuth callback endpoint
- `/oauth/refresh`: Refresh access token requests endpoint
- `/oauth/jwks`: JWKS endpoint
- `/oauth/client-metadata`: Client metadata endpoint

## License

MIT

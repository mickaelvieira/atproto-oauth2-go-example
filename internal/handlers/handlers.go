package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/oauth"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/xrpc"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/database"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/session"
)

func New(s *sessions.CookieStore, st *database.Storage, os oauth.Service) *Handlers {
	return &Handlers{
		Session: s,
		Storage: st,
		OAuth:   os,
	}
}

type Handlers struct {
	Storage *database.Storage
	Session *sessions.CookieStore
	OAuth   oauth.Service
}

func (h *Handlers) addFlash(w http.ResponseWriter, r *http.Request, m string) {
	sess, err := h.Session.Get(r, session.CookieName)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	sess.AddFlash(m)

	if err := sess.Save(r, w); err != nil {
		slog.Error(err.Error())
		return
	}
}

func (h *Handlers) getFlash(w http.ResponseWriter, r *http.Request) string {
	sess, err := h.Session.Get(r, session.CookieName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return ""
	}

	var msg string
	if m := sess.Flashes(); len(m) > 0 {
		msg = fmt.Sprintf(`<article>%s</article>`, m[0])
	}

	if err := sess.Save(r, w); err != nil {
		slog.Error(err.Error())
	}

	return msg
}

func (h *Handlers) Home() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value("user").(*database.User)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write(fmt.Appendf(nil, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="origin-when-cross-origin">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.purple.min.css">
  <title>atproto OAuth Web Service Example</title>
</head>
<body>
<header>
	<hgroup>
		<h1>atproto OAuth Web Service Example</h1>
	</hgroup>
</header>
<main>
	<nav>
	  <ul>
	    <li><a href="/oauth/refresh">Refresh Token</a></li>
	    <li><a href="https://github.com/mickaelvieira/atproto-oauth2-go-example/">Source code</a></li>
	    <li><a href="/oauth/logout">Logout</a></li>
	  </ul>
	</nav>
	<article>
		<h3>Welcome <a href="https://bsky.app/profile/%s" target="_blank" title="%s">%s</a>,</h3>
		<div>
			<div>
				<img src="%s" width="100" height="100" />
			</div>
			<p>%s</p>
			<p>%s</p>
		</div>
	</article>
</main>
</body>
</html>
`, u.Handle, u.DID, u.Handle, u.Avatar, u.DisplayName, u.Description))
	}
}

func (h *Handlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msg := h.getFlash(w, r)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write(fmt.Appendf(nil, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="origin-when-cross-origin">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.purple.min.css">
  <title>atproto OAuth Web Service Example</title>
</head>
<body>
<header>
	<hgroup>
		<h1>atproto OAuth Web Service Example</h1>
	</hgroup>
</header>
<main>
	<article>
		<h3>Login with atproto</h3>
		%s
		<form action="/oauth/login" method="post">
			<p>Provide your handle or DID to authorize an existing account with PDS.</p>
			<fieldset role="group">
		    <input
		      name="handle"
		      placeholder="handle.example.com"
					required
		    />
			  <input
			    type="submit"
			    value="Login"
			  />
		  </fieldset>
			<a href="https://github.com/mickaelvieira/atproto-oauth2-go-example/">
				source code
			</a>
		</form>
</article>
</main>
</body>
</html>
`, msg))
	}
}

func (h *Handlers) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.Session.Get(r, session.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if did, ok := sess.Values["did"].(string); ok {
			if err := h.Storage.OAuth.Delete(did); err != nil {
				slog.Error("failed to delete session", "error", err)
			}

			delete(sess.Values, "did")

			if err := sess.Save(r, w); err != nil {
				slog.Error("failed to save session", "error", err)
			}
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (h *Handlers) LoginToBluesky() http.HandlerFunc {
	directory := identity.NewCacheDirectory(&identity.BaseDirectory{}, 100, time.Hour*24, time.Minute*2, time.Minute*5)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		handle := strings.TrimSpace(r.FormValue("handle"))

		if handle == "" {
			h.addFlash(w, r, "Handle cannot be empty")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var err error
		var ident *identity.Identity
		if atproto.IsDID(handle) {
			ident, err = directory.LookupDID(ctx, syntax.DID(handle))
		} else {
			ident, err = directory.LookupHandle(ctx, syntax.Handle(handle))
		}
		if err != nil {
			h.addFlash(w, r, err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// did:plc:pxtjwskap2gr5mr26ep5m2ii
		pds, err := oauth.FetchPDSResourceMetadata(ident.PDSEndpoint())
		if err != nil {
			h.addFlash(w, r, err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		server, err := oauth.FetchAuthServerMetadata(pds.AuthorizationServers[0])
		if err != nil {
			h.addFlash(w, r, err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		res, _, err := h.OAuth.PushAuthorizationRequest(ctx, ident, server)
		if err != nil {
			h.addFlash(w, r, err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		v := url.Values{}
		v.Set("client_id", h.OAuth.ClientID())
		v.Set("request_uri", res.RequestURI)

		u, err := url.ParseRequestURI(server.AuthorizationEndpoint)
		if err != nil {
			h.addFlash(w, r, err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		u.RawQuery = v.Encode()

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	}
}

func (h *Handlers) OAuthCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		params := oauth.ToCallbackParams(r.URL.Query())

		token, data, err := h.OAuth.RequestAccessToken(ctx, params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sess, err := h.Session.Get(r, session.CookieName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		osess := &database.OAuthSession{
			DID:          token.DID,
			Handle:       data.Handle,
			Nonce:        data.Nonce,
			AuthServer:   data.Issuer,
			AccessToken:  token.AccessToken,
			ExpiresIn:    token.ExpiresIn,
			RefreshToken: token.RefreshToken,
			PrivateKey:   data.DPoPPrivateJWK,
			PDSServer:    data.PDSEndpoint,
		}

		user, err := xrpc.NewClient(osess).Query(r.Context(), "app.bsky.actor.getProfile", map[string]any{
			"actor": osess.DID,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var profile *bsky.ActorDefs_ProfileViewDetailed
		if err := json.Unmarshal(user, &profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		u := &database.User{
			DID:    profile.Did,
			Handle: profile.Handle,
		}
		if profile.Avatar != nil {
			u.Avatar = *profile.Avatar
		}
		if profile.Banner != nil {
			u.Banner = *profile.Banner
		}
		if profile.DisplayName != nil {
			u.DisplayName = *profile.DisplayName
		}
		if profile.Description != nil {
			u.Description = *profile.Description
		}

		if _, err = h.Storage.Users.Upsert(u); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, err = h.Storage.OAuth.Upsert(osess); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sess.Values["did"] = token.DID
		if err := sess.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (h *Handlers) RefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.Session.Get(r, session.CookieName)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		did, ok := sess.Values["did"].(string)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		osess, err := h.Storage.OAuth.Get(did)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if osess.IsExpired() {
			res, err := h.OAuth.RefreshAccessToken(context.Background(), osess)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			osess.Nonce = res.Nonce
			osess.ExpiresIn = res.ExpiresIn
			osess.AccessToken = res.AccessToken
			osess.RefreshToken = res.RefreshToken

			if _, err = h.Storage.OAuth.Upsert(osess); err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (h *Handlers) OAuthJWKHandle() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		priv := h.OAuth.PrivateKey()
		pub := priv.Public()
		jwk, err := json.Marshal(pub)

		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(fmt.Appendf(nil, `{"keys":[%s]}`, jwk))
	}
}

func (h *Handlers) OAuthClientMetadata() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json, err := json.Marshal(h.OAuth.Metadata())
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(json)
	}
}

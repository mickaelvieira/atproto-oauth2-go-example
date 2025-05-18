package session

import (
	"sync"

	"github.com/gorilla/sessions"
)

const (
	CookieName = "atproto-session"
)

var initSession = sync.OnceValue(func() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte("atproto-session"))
})

func Init() *sessions.CookieStore {
	return initSession()
}

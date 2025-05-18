package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/oauth"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/database"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/handlers"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/session"
)

func main() {
	port := flag.String("port", "9000", "The port the web server should listen on")
	host := flag.String("host", "127.0.0.1", "The host the web server is running on")
	flag.Parse()

	s := session.Init()
	d := database.Init()
	st := database.New(d)
	o := oauth.NewClient(*host, os.Getenv("SECRET_JWK"), oauth.WithStorage(
		oauth.NewSQLiteStorage(d),
	))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	h := handlers.New(s, st, o)

	router := mux.NewRouter()
	router.HandleFunc("/", h.Home()).Methods("GET")
	router.HandleFunc("/login", h.Login()).Methods("GET")
	router.HandleFunc("/oauth/login", h.LoginToBluesky()).Methods("POST")
	router.HandleFunc("/oauth/logout", h.Logout()).Methods("GET", "POST")
	router.HandleFunc("/oauth/jwks", h.OAuthJWKHandle()).Methods("GET")
	router.HandleFunc("/oauth/callback", h.OAuthCallback()).Methods("GET")
	router.HandleFunc("/oauth/refresh", h.RefreshToken()).Methods("GET")
	router.HandleFunc("/oauth/client-metadata", h.OAuthClientMetadata()).Methods("GET")

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if r.RequestURI != "/login" && !strings.HasPrefix(r.RequestURI, "/oauth") {
				sess, err := s.Get(r, session.CookieName)
				if err != nil {
					http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
					return
				}

				did, ok := sess.Values["did"].(string)
				if !ok {
					http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
					return
				}

				user, err := st.Users.Get(did)
				if err != nil {
					http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
					return
				}

				r = r.WithContext(context.WithValue(r.Context(), "user", user))
			}

			next.ServeHTTP(w, r)
		})
	})

	ctx, cancel := context.WithCancel(context.Background())

	server := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf(":%s", *port),
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info(fmt.Sprintf("Server listening on port %s", *port))
		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				os.Exit(1)
			}
		}
	}()

	<-stop

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("an error occurred while shutting down the server", "error", err)
	}

	cancel()

	slog.Info("server was successfully shutdown")
}

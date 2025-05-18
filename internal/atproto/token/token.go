package token

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"time"
)

const (
	AlphaNumCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GenRandomString(l int, charset string) string {
	rand.NewSource(time.Now().UnixNano())
	b := make([]byte, l)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func CodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}

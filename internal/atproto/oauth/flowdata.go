package oauth

import (
	"sync"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/atproto/token"
	"github.com/mickaelvieira/atproto-oauth2-go-example/internal/database"
	"gorm.io/gorm"
)

// FlowData carries the data necessary to perform the OAuth authorization workflow
// It is stored in a cache so it can be retrieve between HTTP handlers.
type FlowData struct {
	State          string
	Handle         string
	DID            string
	PKSE           PKCE
	Nonce          string
	Issuer         string
	PDSEndpoint    string
	PAREndpoint    string
	TokenEndpoint  string
	DPoPPrivateJWK []byte
}

func newFlowData(i *identity.Identity, s AuthServerMetadata) *FlowData {
	return &FlowData{
		State:         token.GenRandomString(64, token.AlphaNumCharset),
		DID:           string(i.DID),
		Handle:        string(i.Handle),
		PKSE:          newPKCE(),
		Issuer:        s.Issuer,
		PDSEndpoint:   i.PDSEndpoint(),
		PAREndpoint:   s.PushedAuthorizationRequestEndpoint,
		TokenEndpoint: s.TokenEndpoint,
	}
}

type Storage interface {
	Set(s *FlowData) *FlowData
	Get(s string) *FlowData
	Unset(s string) bool
}

type InMemoryStorage struct {
	lock    sync.Mutex
	storage map[string]*FlowData
}

func defaultStorage() Storage {
	return &InMemoryStorage{
		storage: make(map[string]*FlowData),
	}
}

func (c *InMemoryStorage) Set(s *FlowData) *FlowData {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.storage[s.State] = s

	return s
}

func (c *InMemoryStorage) Get(s string) *FlowData {
	c.lock.Lock()
	defer c.lock.Unlock()

	state, ok := c.storage[s]
	if ok {
		return state
	}
	return nil
}

func (c *InMemoryStorage) Unset(s string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, ok := c.storage[s]
	if ok {
		delete(c.storage, s)
		return true
	}

	return false
}

func NewSQLiteStorage(db *gorm.DB) Storage {
	return &SQLiteStorage{db: db}
}

type SQLiteStorage struct {
	db *gorm.DB
}

func (c *SQLiteStorage) Set(s *FlowData) *FlowData {
	c.db.Create(&database.OAuthFlowData{
		State:         s.State,
		Handle:        s.Handle,
		DID:           s.DID,
		PKSEVerifier:  s.PKSE.Verifier,
		PKSEChallenge: s.PKSE.Challenge,
		PKSEMethod:    s.PKSE.Method,
		Nonce:         s.Nonce,
		Issuer:        s.Issuer,
		PDSEndpoint:   s.PDSEndpoint,
		PAREndpoint:   s.PAREndpoint,
		TokenEndpoint: s.TokenEndpoint,
		PrivateKey:    string(s.DPoPPrivateJWK),
	})
	return s
}

func (c *SQLiteStorage) Get(s string) *FlowData {
	var data *database.OAuthFlowData
	if tx := c.db.Where("state = ?", s).First(&data); tx.Error != nil {
		return nil
	}

	return &FlowData{
		State:  data.State,
		Handle: data.Handle,
		DID:    data.DID,
		PKSE: PKCE{
			Verifier:  data.PKSEVerifier,
			Challenge: data.PKSEChallenge,
			Method:    data.PKSEMethod,
		},
		Nonce:          data.Nonce,
		Issuer:         data.Issuer,
		PDSEndpoint:    data.PDSEndpoint,
		PAREndpoint:    data.PAREndpoint,
		TokenEndpoint:  data.TokenEndpoint,
		DPoPPrivateJWK: []byte(data.PrivateKey),
	}
}

func (c *SQLiteStorage) Unset(s string) bool {
	if tx := c.db.Where("state = ?", s).Delete(&database.OAuthFlowData{}); tx.Error != nil {
		return false
	}
	return true
}

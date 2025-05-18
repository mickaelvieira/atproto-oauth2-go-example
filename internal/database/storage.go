package database

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Storage struct {
	OAuth *OAuthStorage
	Users *UsersStorage
}

func New(db *gorm.DB) *Storage {
	return &Storage{
		OAuth: &OAuthStorage{db: db},
		Users: &UsersStorage{db: db},
	}
}

type OAuthFlowData struct {
	State         string `gorm:"index:idx_oauth_state,unique"`
	Handle        string
	DID           string `gorm:"column:did"`
	PKSEVerifier  string `gorm:"column:pkse_verifier"`
	PKSEChallenge string `gorm:"column:pkse_challenge"`
	PKSEMethod    string `gorm:"column:pkse_method"`
	Nonce         string
	Issuer        string
	PDSEndpoint   string `gorm:"column:pds_endpoint"`
	PAREndpoint   string `gorm:"column:pare_endpoint"`
	TokenEndpoint string
	PrivateKey    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (OAuthFlowData) TableName() string {
	return "oauth_flow_data"
}

type OAuthSession struct {
	ID           uint   `gorm:"primaryKey"`
	DID          string `gorm:"column:did;index:idx_oauth_did,unique"`
	Handle       string
	Nonce        string
	AuthServer   string
	PDSServer    string `gorm:"column:pds_server"`
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
	PrivateKey   []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (OAuthSession) TableName() string {
	return "oauth_sessions"
}

func (o *OAuthSession) IsExpired() bool {
	return time.Since(o.UpdatedAt) >= time.Duration(o.ExpiresIn)*time.Second
}

type OAuthStorage struct {
	db *gorm.DB
}

func (o *OAuthStorage) Get(did string) (*OAuthSession, error) {
	var sess *OAuthSession
	if tx := o.db.Where("did = ?", did).First(&sess); tx.Error != nil {
		return nil, tx.Error
	}
	return sess, nil
}

func (o *OAuthStorage) Delete(did string) error {
	if tx := o.db.Where("did = ?", did).Delete(&OAuthSession{}); tx.Error != nil {
		return tx.Error
	}
	return nil
}

func (o *OAuthStorage) Upsert(m *OAuthSession) (*OAuthSession, error) {
	result := o.db.
		Clauses(
			clause.OnConflict{
				Columns: []clause.Column{{Name: "did"}},
				DoUpdates: clause.AssignmentColumns(
					[]string{
						"handle",
						"nonce",
						"expires_in",
						"access_token",
						"refresh_token",
					}),
			},
		).
		Save(m)

	if result.Error != nil {
		return nil, result.Error
	}
	return m, nil
}

type User struct {
	ID          uint   `gorm:"primaryKey"`
	DID         string `gorm:"column:did;index:idx_user_did,unique"`
	Handle      string
	Avatar      string
	Banner      string
	DisplayName string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UsersStorage struct {
	db *gorm.DB
}

func (o *UsersStorage) Get(did string) (*User, error) {
	var user *User
	if tx := o.db.Where("did = ?", did).First(&user); tx.Error != nil {
		return nil, tx.Error
	}
	return user, nil
}

func (o *UsersStorage) Upsert(m *User) (*User, error) {
	result := o.db.
		Clauses(
			clause.OnConflict{
				Columns: []clause.Column{{Name: "did"}},
				DoUpdates: clause.AssignmentColumns(
					[]string{
						"handle",
						"avatar",
						"banner",
						"display_name",
						"description",
					}),
			},
		).
		Save(m)

	if result.Error != nil {
		return nil, result.Error
	}
	return m, nil
}

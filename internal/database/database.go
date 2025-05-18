package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Init() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("atproto-oauth.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}

	db.AutoMigrate(&OAuthFlowData{})
	db.AutoMigrate(&OAuthSession{})
	db.AutoMigrate(&User{})

	return db
}

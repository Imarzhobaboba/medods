package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Auth struct {
	gorm.Model
	Guid             uuid.UUID `json:"guid" gorm:"type:uuid;primaryKey"`
	RefreshTokenHash string    `json:"refresh_token_hash"`
	UserAgent        string    `json:"user_agent"`
	Ip               string    `json:"ip"`
	IsValid          bool      `json:"is_valid" gorm:"default:true"` // Активен ли токен
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Auth{})
}

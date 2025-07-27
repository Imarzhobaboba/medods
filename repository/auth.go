package repository

import (
	"github.com/Imarzhobaboba/medods/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// CreateAuth сохраняет запись о refresh-токене
func (r *AuthRepository) CreateAuth(auth *models.Auth) error {
	return r.db.Create(auth).Error
}

// FindByGuid ищет запись по GUID
func (r *AuthRepository) FindByGuid(guid uuid.UUID) (*models.Auth, error) {
	var auth models.Auth
	err := r.db.Where("guid = ? AND is_valid = true", guid).First(&auth).Error
	return &auth, err
}

// InvalidateRefreshToken помечает токен как невалидный
func (r *AuthRepository) InvalidateRefreshToken(guid uuid.UUID) error {
	return r.db.Model(&models.Auth{}).Where("guid = ?", guid).Update("is_valid", false).Error
}

// FindByRefreshToken ищет запись по хешу refresh токена
func (r *AuthRepository) FindByRefreshToken(tokenHash string) (*models.Auth, error) {
	var auth models.Auth
	err := r.db.Where("refresh_token_hash = ?", tokenHash).First(&auth).Error
	return &auth, err
}

// InvalidateAllTokens помечает все токены пользователя как невалидные
func (r *AuthRepository) InvalidateAllTokens(guid uuid.UUID) error {
	return r.db.Model(&models.Auth{}).Where("guid = ?", guid).Update("is_valid", false).Error
}

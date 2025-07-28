package repository

import (
	"github.com/Imarzhobaboba/medods/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
func (r *AuthRepository) FindByRefreshToken(token string) (*models.Auth, error) {
	// Получаем все активные записи для данного токена (можно добавить фильтр по IsValid если нужно)
	var authRecords []models.Auth
	if err := r.db.Find(&authRecords).Error; err != nil {
		return nil, err
	}

	// Проверяем каждый хеш с помощью bcrypt
	for _, record := range authRecords {
		err := bcrypt.CompareHashAndPassword([]byte(record.RefreshTokenHash), []byte(token))
		if err == nil {
			return &record, nil
		}
	}

	return nil, gorm.ErrRecordNotFound
}

// InvalidateAllTokens помечает все токены пользователя как невалидные
func (r *AuthRepository) InvalidateAllTokens(guid uuid.UUID) error {
	return r.db.Model(&models.Auth{}).Where("guid = ?", guid).Update("is_valid", false).Error
}

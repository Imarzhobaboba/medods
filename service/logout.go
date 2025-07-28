package service

import (
	"errors"

	"github.com/Imarzhobaboba/medods/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type LogoutService struct {
	repo      *repository.AuthRepository
	jwtSecret []byte
}

func NewLogoutService(repo *repository.AuthRepository, jwtSecret string) *LogoutService {
	return &LogoutService{
		repo:      repo,
		jwtSecret: []byte(jwtSecret),
	}
}

// Logout инвалидирует все refresh токены пользователя
func (s *LogoutService) Logout(accessToken string) error {
	// 1. Парсим access token чтобы получить GUID
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return errors.New("invalid access token")
	}

	// 2. Извлекаем GUID из токена
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid token claims")
	}

	guidStr, ok := claims["guid"].(string)
	if !ok {
		return errors.New("guid not found in token")
	}

	guid, err := uuid.Parse(guidStr)
	if err != nil {
		return errors.New("invalid guid format")
	}

	// 3. Инвалидируем все refresh токены пользователя
	return s.repo.InvalidateAllTokens(guid)
}

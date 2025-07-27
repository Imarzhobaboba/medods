package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Imarzhobaboba/medods/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RefreshService struct {
	repo       *repository.AuthRepository
	jwtSecret  []byte
	webhookURL string // URL для отправки уведомлений о новых IP
}

func NewRefreshService(repo *repository.AuthRepository, jwtSecret string, webhookURL string) *RefreshService {
	return &RefreshService{
		repo:       repo,
		jwtSecret:  []byte(jwtSecret),
		webhookURL: webhookURL,
	}
}

// RefreshTokens обновляет пару токенов
func (s *RefreshService) RefreshTokens(oldAccessToken, oldRefreshToken, userAgent, ip string) (newAccessToken, newRefreshToken string, err error) {
	// 1. Проверяем старый access token (формат и подпись)
	_, err = jwt.Parse(oldAccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return "", "", errors.New("invalid access token")
	}

	// 2. Декодируем refresh token из base64
	decodedRefresh, err := base64.StdEncoding.DecodeString(oldRefreshToken)
	if err != nil {
		return "", "", errors.New("invalid refresh token format")
	}

	// 3. Ищем запись в БД по refresh token
	authRecord, err := s.repo.FindByRefreshToken(string(decodedRefresh))
	if err != nil {
		return "", "", errors.New("refresh token not found")
	}

	// 4. Проверяем валидность токена
	if !authRecord.IsValid {
		return "", "", errors.New("refresh token expired")
	}

	// 5. Проверяем User-Agent
	if authRecord.UserAgent != userAgent {
		// Инвалидируем все токены пользователя
		_ = s.repo.InvalidateAllTokens(authRecord.Guid)
		return "", "", errors.New("user agent mismatch")
	}

	// 6. Если IP изменился - отправляем webhook
	if authRecord.Ip != ip {
		go s.sendIPChangeWebhook(authRecord.Guid, authRecord.Ip, ip)
	}

	// 7. Генерируем новую пару токенов
	newAccessToken, newRefreshToken, err = s.generateNewTokenPair(authRecord.Guid, userAgent, ip)
	if err != nil {
		return "", "", err
	}

	// 8. Инвалидируем старый refresh token
	if err := s.repo.InvalidateRefreshToken(authRecord.Guid); err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

// Вспомогательные методы
func (s *RefreshService) generateNewTokenPair(guid uuid.UUID, userAgent, ip string) (string, string, error) {
	// Аналогично GenerateTokens из auth.go
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid.String(),
		"exp":  time.Now().Add(15 * time.Minute).Unix(), // Access token живёт 15 минут
	})

	buf := make([]byte, 32) // 32 байта это длина refresh токена
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return token.SignedString(s.jwtSecret), base64.StdEncoding.EncodeToString(buf), nil
}

func (s *RefreshService) sendIPChangeWebhook(guid uuid.UUID, oldIP, newIP string) {
	// Реализация отправки webhook
	// ...
}

package service

import (
	"github.com/Imarzhobaboba/medods/models"
	"github.com/Imarzhobaboba/medods/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	repo      *repository.AuthRepository
	jwtSecret []byte
}

func NewAuthService(repo *repository.AuthRepository, jwtSecret string) *AuthService {
	return &AuthService{
		repo:      repo,
		jwtSecret: []byte(jwtSecret),
	}
}

// GenerateTokens создаёт access и refresh токены
func (s *AuthService) GenerateTokens(guid uuid.UUID, userAgent, ip string) (accessToken, refreshToken string, err error) {
	// 1. Генерация access token (JWT)
	accessToken, err = generateAccessToken(guid, s.jwtSecret)
	if err != nil {
		return "", "", err
	}

	// 2. Генерация refresh token (рандомная строка теперь base64)
	refreshToken, err = generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	// 3. Хеширование refresh token (для сохранения в БД)
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	// 4. Сохранение в БД
	authRecord := &models.Auth{
		Guid:             guid,
		RefreshTokenHash: string(refreshTokenHash),
		UserAgent:        userAgent,
		Ip:               ip,
		IsValid:          true,
	}

	if err := s.repo.CreateAuth(authRecord); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// // generateAccessToken создаёт JWT токен
// func (s *AuthService) generateAccessToken(guid uuid.UUID) (string, error) {
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
// 		"guid": guid.String(),
// 		"exp":  time.Now().Add(15 * time.Minute).Unix(), // Access token живёт 15 минут
// 	})

// 	return token.SignedString(s.jwtSecret)
// }

// // generateRefreshToken создаёт случайный токен в base64
// func (s *AuthService) generateRefreshToken() (string, error) {
// 	buf := make([]byte, 32) // 32 байта это длина refresh токена
// 	if _, err := rand.Read(buf); err != nil {
// 		return "", err
// 	}
// 	return base64.StdEncoding.EncodeToString(buf), nil
// }

package service

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// generateAccessToken создаёт JWT токен
func generateAccessToken(guid uuid.UUID, jwtSecret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid.String(),
		"exp":  time.Now().Add(15 * time.Minute).Unix(), // Access token живёт 15 минут
	})

	return token.SignedString(jwtSecret)
}

// generateRefreshToken создаёт случайный токен в base64
func generateRefreshToken() (string, error) {
	buf := make([]byte, 32) // 32 байта это длина refresh токена
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

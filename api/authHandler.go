package api

import (
	"net/http"

	"github.com/Imarzhobaboba/medods/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(service *service.AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

// AuthRequest — тело запроса для /auth
type AuthRequest struct {
	Guid uuid.UUID `json:"guid" binding:"required"`
}

// AuthResponse — ответ с токенами
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// CreateAuthHandler обрабатывает POST /auth
func (h *AuthHandler) CreateAuthHandler(c *gin.Context) {
	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid GUID"})
		return
	}

	// Получаем User-Agent и IP из запроса
	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	// Генерируем токены
	accessToken, refreshToken, err := h.service.GenerateTokens(req.Guid, userAgent, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// Здесь хэндлер для refresh. Его надо будет перенести в отдельный файл

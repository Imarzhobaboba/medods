package api

import (
	"net/http"
	"strings"

	"github.com/Imarzhobaboba/medods/service"
	"github.com/gin-gonic/gin"
)

type LogoutHandler struct {
	service *service.LogoutService
}

func NewLogoutHandler(service *service.LogoutService) *LogoutHandler {
	return &LogoutHandler{service: service}
}

// // AuthRequest — тело запроса для /auth
// type LogoutRequest struct {
// 	Guid uuid.UUID `json:"guid" binding:"required"`
// }

// // AuthResponse — ответ с токенами
// type LogoutResponse struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// }

// LogoutHandler обрабатывает POST /logout
func (h *LogoutHandler) LogoutHandler(c *gin.Context) {
	// Получаем access token из контекста (уже проверен в middleware)
	authHeader := c.GetHeader("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	if err := h.service.Logout(token); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

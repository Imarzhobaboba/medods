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

// LogoutHandler обрабатывает POST /logout

// @Summary Выход из системы
// @Description Инвалидирует переданный токен
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string "Успешный выход"
// @Failure 401 {object} map[string]string "Ошибка выхода"
// @Router /logout [post]
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

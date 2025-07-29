package api

import (
	"net/http"

	"github.com/Imarzhobaboba/medods/service"

	"github.com/gin-gonic/gin"
)

type RefreshHandler struct {
	service *service.RefreshService
}

func NewRefreshHandler(service *service.RefreshService) *RefreshHandler {
	return &RefreshHandler{service: service}
}

// RefreshRequest - тело запроса для /refresh
type RefreshRequest struct {
	AccessToken  string `json:"access_token" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshHandler обрабатывает POST /refresh

// @title Medods Auth API
// @version 1.0
// @description API для аутентификации через JWT токены
// @host localhost:8080
// @BasePath /

// AuthRequest godoc
// @Summary Получить токены
// @Description Генерирует access и refresh токены для указанного GUID
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body RefreshRequest true "access токен и refresh токен"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /refresh [post]
func (h *RefreshHandler) RefreshHandler(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	newAccess, newRefresh, err := h.service.RefreshTokens(req.AccessToken, req.RefreshToken, userAgent, ip)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

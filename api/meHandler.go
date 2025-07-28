package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type MeHandler struct {
	jwtSecret []byte
}

func NewMeHandler(jwtSecret string) *MeHandler {
	return &MeHandler{jwtSecret: []byte(jwtSecret)}
}

// type MeRequest struct {
// 	Guid uuid.UUID `json:"guid" binding:"required"`
// }

type MeResponse struct {
	Guid string `json:"guid"`
}

func (h *MeHandler) MeHandler(c *gin.Context) {
	// Получаем GUID из контекста (установленного в middleware)
	guid, exists := c.Get("guid")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	c.JSON(http.StatusOK, MeResponse{
		Guid: guid.(string),
	})
}

package main

import (
	"log"
	"os"

	"github.com/Imarzhobaboba/medods/api"
	"github.com/Imarzhobaboba/medods/database"
	_ "github.com/Imarzhobaboba/medods/docs"
	"github.com/Imarzhobaboba/medods/models"
	"github.com/Imarzhobaboba/medods/repository"
	"github.com/Imarzhobaboba/medods/service"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Auth API
// @version 1.0
// @description API для авторизации

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @Security BearerAuth
// @param Authorization header string true "Authentication" default(Bearer <token>)

// @host localhost:8080
// @BasePath /
func main() {
	// Инициализация БД
	db := database.SetupDB()
	models.AutoMigrate(db)

	// Инициализация слоёв
	authRepo := repository.NewAuthRepository(db)
	authService := service.NewAuthService(authRepo, os.Getenv("SECRET"))
	authHandler := api.NewAuthHandler(authService)

	refreshService := service.NewRefreshService(authRepo, os.Getenv("SECRET"), os.Getenv("WEBHOOK_URL"))
	refreshHandler := api.NewRefreshHandler(refreshService)

	meHandler := api.NewMeHandler(os.Getenv("SECRET"))

	logoutService := service.NewLogoutService(authRepo, os.Getenv("SECRET"))
	logoutHandler := api.NewLogoutHandler(logoutService)

	// Настройка роутера
	r := gin.Default()

	// Swagger UI
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Защищённые эндпоинты
	authGroup := r.Group("/")
	authGroup.Use(meHandler.Middleware())
	{
		authGroup.GET("/me", meHandler.MeHandler)
		authGroup.POST("/logout", logoutHandler.LogoutHandler)
	}

	// Роуты
	r.POST("/auth", authHandler.CreateAuthHandler)
	r.POST("/refresh", refreshHandler.RefreshHandler)

	// Запуск сервера
	log.Println("Server running on :8080")
	r.Run(":8080")
}

package main

import (
	"log"
	"os"

	"github.com/Imarzhobaboba/medods/api"
	"github.com/Imarzhobaboba/medods/database"
	"github.com/Imarzhobaboba/medods/models"
	"github.com/Imarzhobaboba/medods/repository"
	"github.com/Imarzhobaboba/medods/service"
	"github.com/gin-gonic/gin"
)

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

	// Настройка роутера
	r := gin.Default()

	// Защищённые эндпоинты
	authGroup := r.Group("/")
	authGroup.Use(meHandler.Middleware())
	{
		authGroup.GET("/me", meHandler.MeHandler)
		// Здесь позже добавим /logout
	}

	// Роуты
	r.POST("/auth", authHandler.CreateAuthHandler)
	r.POST("/refresh", refreshHandler.RefreshHandler)

	// Запуск сервера
	log.Println("Server running on :8080")
	r.Run(":8080")
}

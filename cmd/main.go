package main

import (
	"log"
	"os"

	"github.com/ShriiiGaikwad/KaiSecurity/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Using default values.")
	}

	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data.db" // Default if not set
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	store.InitDB(dbPath)

	r := gin.Default()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.Static("/static", "./web")

	r.GET("/", func(c *gin.Context) {
		c.File("./web/index.html")
	})

	r.POST("/scan", ScanRepo)
	r.POST("/query", QueryData)

	log.Printf("Starting server on port %s...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

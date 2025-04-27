package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	server "github.com/BazaarTrade/AuthService/internal/api/gRPC"
	"github.com/BazaarTrade/AuthService/internal/repository/postgresPgx"
	"github.com/BazaarTrade/AuthService/internal/service"
	"github.com/joho/godotenv"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	logger.Info("starting application...")

	//load .env file if it exists
	//i use this to load the env variables from docker compose
	if _, err := os.Stat("../.env"); err == nil {
		if err := godotenv.Load("../.env"); err != nil {
			logger.Error("failed to load .env file", "error", err)
			return
		}
	}

	DB_CONNECTION := os.Getenv("DB_CONNECTION")
	if DB_CONNECTION == "" {
		logger.Error("DB_CONNECTION environment variable is not set")
		return
	}

	repository, err := postgresPgx.New(DB_CONNECTION, logger)
	if err != nil {
		return
	}

	service := service.New(repository, logger)
	server := server.New(service, logger)

	GRPC_PORT := os.Getenv("GRPC_PORT")
	if GRPC_PORT == "" {
		logger.Error("GRPC_PORT environment variable is not set")
		return
	}

	go func() {
		if err := server.Run(GRPC_PORT); err != nil {
			os.Exit(1)
		}
	}()

	//Graceful shutdown

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	<-stop

	server.Stop()
	repository.Close()

	logger.Info("gracefully stopped")
}

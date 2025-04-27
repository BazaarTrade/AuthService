package service

import (
	"errors"
	"log/slog"
	"os"

	"github.com/BazaarTrade/AuthService/internal/repository"
	"github.com/BazaarTrade/AuthService/internal/tokenManager"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrWrongPassword            = errors.New("wrong password")
	ErrRefreshTokenSecretNotSet = errors.New("REFRESH_TOKEN_SECRET_PHRASE environment variable is not set")
	ErrRefreshTokenNotFound     = errors.New("refresh token not found")
)

type Service struct {
	repository               repository.Repository
	refreshTokenSecretPhrase string
	logger                   *slog.Logger
}

func New(repository repository.Repository, logger *slog.Logger) *Service {
	REFRESH_TOKEN_SECRET_PHRASE := os.Getenv("REFRESH_TOKEN_SECRET_PHRASE")
	if REFRESH_TOKEN_SECRET_PHRASE == "" {
		logger.Error("failed to get REFRESH_TOKEN_SECRET_PHRASE")
		return nil
	}

	return &Service{
		repository:               repository,
		refreshTokenSecretPhrase: REFRESH_TOKEN_SECRET_PHRASE,
		logger:                   logger,
	}
}

func (s *Service) Register(email string, password string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("failed to generate password hash", "error", err)
		return err
	}

	err = s.repository.CreateUser(email, string(passwordHash))
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) Login(email string, password string) (int, string, error) {
	userID, passwordHash, err := s.repository.GetUserByEmail(email)
	if err != nil {
		return 0, "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return 0, "", ErrWrongPassword
	}

	refreshToken, err := tokenManager.GenerateRefreshToken(userID, s.refreshTokenSecretPhrase)
	if err != nil {
		s.logger.Error("failed to generate refresh token", "error", err)
		return 0, "", err
	}

	err = s.repository.NewRefreshToken(userID, refreshToken)
	if err != nil {
		return 0, "", err
	}

	return userID, refreshToken, nil
}

func (s *Service) Logout(refreshToken string) error {
	err := s.repository.DeleteSession(refreshToken)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) IsRefreshTokenValid(userID int, refreshToken string) (bool, string, error) {
	exists, err := s.repository.FindRefreshToken(refreshToken)
	if err != nil {
		return false, "", err
	}

	if !exists {
		return false, "", ErrRefreshTokenNotFound
	}

	isValid, err := tokenManager.IsRefreshTokenValid(userID, refreshToken, s.refreshTokenSecretPhrase)
	if err != nil {
		s.logger.Error("failed to check refresh token expiration", "error", err)
		return false, "", err
	}

	if !isValid {
		return false, "", nil
	}

	isCloseToExpire, err := tokenManager.WillExpireInLessThenADay(refreshToken, s.refreshTokenSecretPhrase)
	if err != nil {
		s.logger.Error("failed to check refresh token expiration", "error", err)
		return false, "", err
	}

	if !isCloseToExpire {
		return true, "", nil
	}

	//if refresh token will expire in less then a day, generate a new one
	newRefreshToken, err := tokenManager.GenerateRefreshToken(userID, s.refreshTokenSecretPhrase)
	if err != nil {
		s.logger.Error("failed to generate refresh token", "error", err)
		return false, "", err
	}

	err = s.repository.NewRefreshToken(userID, newRefreshToken)
	if err != nil {
		return false, "", err
	}

	return true, newRefreshToken, nil
}

func (s *Service) ChangePassword(email string, oldPassword string, newPassword string, refreshToken string) error {
	_, passwordHash, err := s.repository.GetUserByEmail(email)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(oldPassword))
	if err != nil {
		return ErrWrongPassword
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("failed to generate password hash", "error", err)
		return err
	}

	err = s.repository.ChangePassword(email, string(newPasswordHash))
	if err != nil {
		return err
	}

	err = s.repository.DeleteSession(refreshToken)
	if err != nil {
		return err
	}

	return nil
}

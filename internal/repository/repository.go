package repository

import "errors"

type Repository interface {
	CreateUser(email string, passwordHash string) error
	GetUserByEmail(email string) (int, string, error)
	FindRefreshToken(refreshToken string) (bool, error)
	NewRefreshToken(userID int, refreshToken string) error
	DeleteSession(refreshToken string) error
	ChangePassword(email string, newPasswordHash string) error
}

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

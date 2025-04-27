package server

import (
	"context"
	"errors"
	"net/mail"

	"github.com/BazaarTrade/AuthProtoGen/pbA"
	"github.com/BazaarTrade/AuthService/internal/repository"
	"github.com/BazaarTrade/AuthService/internal/service"
	"github.com/BazaarTrade/AuthService/internal/tokenManager"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Register(ctx context.Context, req *pbA.RegisterRequest) (*pbA.RegisterResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	_, err := mail.ParseAddress(req.Email)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email address")
	}

	if len(req.Password) < 4 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 4 characters long")
	}

	err = s.service.Register(req.Email, req.Password)
	if err != nil {
		if err == repository.ErrUserExists {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &pbA.RegisterResponse{}, nil
}

func (s *Server) Login(ctx context.Context, req *pbA.LoginRequest) (*pbA.LoginResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	userID, refreshToken, err := s.service.Login(req.Email, req.Password)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		if err == service.ErrWrongPassword {
			return nil, status.Error(codes.Unauthenticated, "wrong password")
		}

		if err == service.ErrRefreshTokenSecretNotSet {
			return nil, status.Error(codes.Internal, "refresh token secret not set")
		}
	}

	return &pbA.LoginResponse{UserID: int64(userID), RefreshToken: refreshToken}, nil
}

func (s *Server) Logout(ctx context.Context, req *pbA.LogoutRequest) (*pbA.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refreshToken is required")
	}

	err := s.service.Logout(req.RefreshToken)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to log out user")
	}

	return &pbA.LogoutResponse{}, nil
}

func (s *Server) IsRefreshTokenValid(ctx context.Context, req *pbA.IsRefreshTokenValidRequest) (*pbA.IsRefreshTokenValidResponse, error) {
	if req.UserID == 0 {
		return nil, status.Error(codes.InvalidArgument, "userID is required")
	}

	if req.RefreshToken == "" {
		return nil, status.Error(codes.Unauthenticated, "refresh token is required")
	}

	isValid, newRefreshToken, err := s.service.IsRefreshTokenValid(int(req.UserID), req.RefreshToken)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		if err == service.ErrRefreshTokenSecretNotSet {
			return nil, status.Error(codes.Internal, "refresh token secret not set")
		}

		if errors.Is(err, tokenManager.ErrInvalidToken) || errors.Is(err, service.ErrRefreshTokenNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}

		return nil, status.Error(codes.Internal, "failed to check refresh token validity")
	}

	if !isValid {
		return &pbA.IsRefreshTokenValidResponse{IsValid: false}, nil
	}

	return &pbA.IsRefreshTokenValidResponse{IsValid: isValid, NewRefreshToken: newRefreshToken}, nil
}

func (s *Server) ChangePassword(ctx context.Context, req *pbA.ChangePasswordRequest) (*pbA.ChangePasswordResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	if len(req.OldPassword) < 4 {
		return nil, status.Error(codes.InvalidArgument, "old password must be at least 4 characters long")
	}

	if len(req.NewPassword) < 4 {
		return nil, status.Error(codes.InvalidArgument, "new password must be at least 4 characters long")
	}

	if req.NewPassword == req.OldPassword {
		return nil, status.Error(codes.InvalidArgument, "new password must be different from old password")
	}

	if err := s.service.ChangePassword(req.Email, req.OldPassword, req.NewPassword, req.RefreshToken); err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		if err == service.ErrWrongPassword {
			return nil, status.Error(codes.InvalidArgument, "wrong password")
		}

		return nil, status.Error(codes.Internal, "failed to change password")
	}

	return &pbA.ChangePasswordResponse{}, nil
}

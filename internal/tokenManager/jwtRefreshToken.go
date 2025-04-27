package tokenManager

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	//ErrInvalidToken is a group of errors
	ErrInvalidToken = errors.New("invalid token")

	ErrUnexpectedSigningMethod = errors.Join(ErrInvalidToken, errors.New("unexpected signing method"))
	ErrInvalidTokenClaims      = errors.Join(ErrInvalidToken, errors.New("invalid token claims"))
)

func GenerateRefreshToken(userID int, REFRESH_TOKEN_SECRET_PHRASE string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour * 24 * 30).Unix(), // 30 days expiration
	})

	signedToken, err := token.SignedString([]byte(REFRESH_TOKEN_SECRET_PHRASE))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func IsRefreshTokenValid(userID int, refreshToken string, REFRESH_TOKEN_SECRET_PHRASE string) (bool, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(REFRESH_TOKEN_SECRET_PHRASE), nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// check expiration time
		exp, ok := claims["exp"].(float64)
		if !ok {
			return false, ErrInvalidTokenClaims
		}
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return false, nil
		}

		// check userID
		userIDToken, ok := claims["userID"].(float64)
		if !ok {
			return false, ErrInvalidTokenClaims
		}

		if int(userIDToken) != userID {
			return false, nil
		}

		return true, nil
	}

	return false, ErrInvalidTokenClaims
}

func WillExpireInLessThenADay(tokenString string, REFRESH_TOKEN_SECRET_PHRASE string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(REFRESH_TOKEN_SECRET_PHRASE), nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		exp, ok := claims["exp"].(float64)
		if !ok {
			return false, ErrInvalidTokenClaims
		}
		expTime := time.Unix(int64(exp), 0)
		if time.Until(expTime) < time.Hour*24 {
			return true, nil
		}
		return false, nil
	}

	return false, ErrInvalidTokenClaims
}

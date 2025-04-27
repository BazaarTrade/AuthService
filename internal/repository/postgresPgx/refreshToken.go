package postgresPgx

import (
	"context"

	"github.com/BazaarTrade/AuthService/internal/repository"
)

func (p *Postgres) NewRefreshToken(userID int, refreshToken string) error {
	_, err := p.db.Exec(context.Background(), `
		INSERT INTO auth.sessions (userID, refreshToken, expiresAt)
		VALUES ($1, $2, NOW() + INTERVAL '1 MONTH')
	`, userID, refreshToken)
	if err != nil {
		p.logger.Error("failed to change refresh token", "error", err)
		return err
	}
	return nil
}

func (p *Postgres) FindRefreshToken(refreshToken string) (bool, error) {
	var exists bool
	err := p.db.QueryRow(context.Background(), `
		SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE refreshToken = $1)
	`, refreshToken).Scan(&exists)

	if err != nil {
		p.logger.Error("failed to check refresh token", "error", err)
		return false, err
	}

	return exists, nil
}

func (p *Postgres) DeleteSession(refreshToken string) error {
	tag, err := p.db.Exec(context.Background(), `
		DELETE FROM auth.sessions
		WHERE refreshToken = $1
	`, refreshToken)
	if err != nil {
		p.logger.Error("failed to delete refresh token", "error", err)
		return err
	}

	if tag.RowsAffected() == 0 {
		return repository.ErrUserNotFound
	}

	return nil
}

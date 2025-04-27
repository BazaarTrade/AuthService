package postgresPgx

import (
	"context"
	"errors"

	"github.com/BazaarTrade/AuthService/internal/repository"
	"github.com/jackc/pgx/v5"
)

func (p *Postgres) CreateUser(email string, passwordHash string) error {
	tag, err := p.db.Exec(context.Background(), `
		INSERT INTO auth.users (email, passwordHash)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, email, passwordHash)

	if err != nil {
		p.logger.Error("failed to insert user", "error", err)
		return err
	}

	if tag.RowsAffected() == 0 {
		return repository.ErrUserExists
	}

	return nil
}

func (p *Postgres) GetUserByEmail(email string) (int, string, error) {
	var (
		userID       int
		passwordHash string
	)
	err := p.db.QueryRow(context.Background(), `
	SELECT userID, passwordHash 
	FROM auth.users 
	WHERE email = $1
	`, email).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", repository.ErrUserNotFound
		}

		p.logger.Error("failed to get user by email", "error", err)
		return 0, "", err
	}
	return userID, passwordHash, nil
}

func (p *Postgres) ChangePassword(email string, newPasswordHash string) error {
	_, err := p.db.Exec(context.Background(), `
	UPDATE auth.users 
	SET passwordHash = $1 
	WHERE email = $2
	`, newPasswordHash, email)
	if err != nil {
		p.logger.Error("failed to change password", "error", err)
		return err
	}
	return nil
}

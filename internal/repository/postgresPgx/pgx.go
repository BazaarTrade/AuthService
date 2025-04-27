package postgresPgx

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

func New(DB_CONNECTION string, logger *slog.Logger) (*Postgres, error) {
	var (
		p   = &Postgres{logger: logger}
		err error
	)

	p.db, err = pgxpool.New(context.Background(), DB_CONNECTION)
	if err != nil {
		logger.Error("failed to create pgxPool connection", "error", err)
		return nil, err
	}

	err = p.createTables()
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Postgres) createTables() error {
	_, err := p.db.Exec(context.Background(), `
	CREATE SCHEMA IF NOT EXISTS auth;

	CREATE TABLE IF NOT EXISTS auth.users (
		userID SERIAL PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		passwordHash TEXT NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS auth.sessions (
		sessionID SERIAL PRIMARY KEY,
		userID INT REFERENCES auth.users(userID) ON DELETE CASCADE,
		refreshToken TEXT NOT NULL UNIQUE,
		createdAt TIMESTAMP NOT NULL DEFAULT NOW(),
		expiresAt TIMESTAMP NOT NULL
	);
`)
	if err != nil {
		p.logger.Error("failed to create tables", "error", err)
		return err
	}
	return nil
}

func (p *Postgres) Close() {
	p.db.Close()
}

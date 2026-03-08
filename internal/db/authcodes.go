package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type AuthCode struct {
	CodeHash            string
	ClientID            string
	Email               string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ProfileSnapshot     string
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

func (d *DB) CreateAuthCode(code *AuthCode) error {
	_, err := d.Exec(
		`INSERT INTO authorization_codes
		(code_hash, client_id, email, redirect_uri, scope, nonce, code_challenge, code_challenge_method, profile_snapshot, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code.CodeHash, code.ClientID, code.Email, code.RedirectURI,
		code.Scope, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod,
		code.ProfileSnapshot, code.ExpiresAt.UTC().Format(time.DateTime),
	)
	return err
}

func (d *DB) GetAuthCode(codeHash string) (*AuthCode, error) {
	ac := &AuthCode{}
	var expiresAtStr string
	var usedAtStr sql.NullString
	err := d.QueryRow(
		`SELECT code_hash, client_id, email, redirect_uri, scope, nonce,
		code_challenge, code_challenge_method, profile_snapshot, expires_at, used_at
		FROM authorization_codes WHERE code_hash = ?`,
		codeHash,
	).Scan(
		&ac.CodeHash, &ac.ClientID, &ac.Email, &ac.RedirectURI,
		&ac.Scope, &ac.Nonce, &ac.CodeChallenge, &ac.CodeChallengeMethod,
		&ac.ProfileSnapshot, &expiresAtStr, &usedAtStr,
	)
	if err != nil {
		return nil, err
	}
	ac.ExpiresAt, err = parseFlexibleTime(expiresAtStr)
	if err != nil {
		return nil, fmt.Errorf("parsing expires_at: %w", err)
	}
	if usedAtStr.Valid {
		t, err := parseFlexibleTime(usedAtStr.String)
		if err != nil {
			return nil, fmt.Errorf("parsing used_at: %w", err)
		}
		ac.UsedAt = &t
	}
	return ac, nil
}

func parseFlexibleTime(s string) (time.Time, error) {
	formats := []string{
		time.DateTime,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}

func (d *DB) CleanupExpiredCodes(ctx context.Context) (int64, error) {
	result, err := d.ExecContext(ctx,
		`DELETE FROM authorization_codes WHERE expires_at < datetime('now') OR (used_at IS NOT NULL AND used_at < datetime('now', '-1 hour'))`,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) MarkAuthCodeUsed(codeHash string) error {
	result, err := d.Exec(
		"UPDATE authorization_codes SET used_at = datetime('now') WHERE code_hash = ? AND used_at IS NULL",
		codeHash,
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("authorization code already used or not found")
	}
	return nil
}

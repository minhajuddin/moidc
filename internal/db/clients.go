package db

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

type Client struct {
	ClientID         string   `json:"client_id"`
	ClientSecretHash string   `json:"-"`
	ClientName       string   `json:"client_name"`
	Email            string   `json:"email"`
	RedirectURIs     []string `json:"redirect_uris"`
}

func (d *DB) CreateClient(clientID, clientSecret, clientName, email string, redirectURIs []string) error {
	hash := sha256Hash(clientSecret)
	urisJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return fmt.Errorf("marshaling redirect_uris: %w", err)
	}
	_, err = d.Exec(
		"INSERT INTO clients (client_id, client_secret_hash, client_name, email, redirect_uris) VALUES (?, ?, ?, ?, ?)",
		clientID, hash, clientName, email, string(urisJSON),
	)
	return err
}

func (d *DB) GetClient(clientID string) (*Client, error) {
	c := &Client{}
	var urisJSON string
	err := d.QueryRow(
		"SELECT client_id, client_secret_hash, client_name, email, redirect_uris FROM clients WHERE client_id = ?",
		clientID,
	).Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &c.Email, &urisJSON)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshaling redirect_uris: %w", err)
	}
	return c, nil
}

func (d *DB) ValidateClientSecret(clientID, clientSecret string) (*Client, error) {
	client, err := d.GetClient(clientID)
	if err != nil {
		return nil, err
	}
	if client.ClientSecretHash != sha256Hash(clientSecret) {
		return nil, fmt.Errorf("invalid client secret")
	}
	return client, nil
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

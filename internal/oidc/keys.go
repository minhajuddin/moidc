package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/minhajuddin/moidc/internal/db"
)

type KeyManager struct {
	db         *db.DB
	signingKey *rsa.PrivateKey
	signingKID string
	encKey     []byte // AES-256 key for JWE access tokens
	encKID     string
}

func NewKeyManager(database *db.DB) (*KeyManager, error) {
	km := &KeyManager{db: database}
	if err := km.ensureSigningKey(); err != nil {
		return nil, fmt.Errorf("ensuring signing key: %w", err)
	}
	if err := km.ensureEncryptionKey(); err != nil {
		return nil, fmt.Errorf("ensuring encryption key: %w", err)
	}
	return km, nil
}

func (km *KeyManager) ensureSigningKey() error {
	key, err := km.db.GetActiveSigningKey("signing")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if key != nil {
		block, _ := pem.Decode([]byte(key.PrivateKeyPEM))
		if block == nil {
			return fmt.Errorf("failed to decode PEM block")
		}
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing private key: %w", err)
		}
		km.signingKey = privKey
		km.signingKID = key.KID
		slog.Info("loaded existing signing key", "kid", key.KID)
		return nil
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	kid, err := generateKID()
	if err != nil {
		return err
	}
	if err := km.db.CreateSigningKey(kid, string(pemBytes), "RS256", "signing"); err != nil {
		return fmt.Errorf("storing signing key: %w", err)
	}

	km.signingKey = privKey
	km.signingKID = kid
	slog.Info("generated new signing key", "kid", kid)
	return nil
}

func (km *KeyManager) ensureEncryptionKey() error {
	key, err := km.db.GetActiveSigningKey("encryption")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if key != nil {
		b, err := hex.DecodeString(key.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("decoding encryption key: %w", err)
		}
		km.encKey = b
		km.encKID = key.KID
		slog.Info("loaded existing encryption key", "kid", key.KID)
		return nil
	}

	aesKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("generating AES key: %w", err)
	}

	kid, err := generateKID()
	if err != nil {
		return err
	}
	if err := km.db.CreateSigningKey(kid, hex.EncodeToString(aesKey), "A256GCM", "encryption"); err != nil {
		return fmt.Errorf("storing encryption key: %w", err)
	}

	km.encKey = aesKey
	km.encKID = kid
	slog.Info("generated new encryption key", "kid", kid)
	return nil
}

func (km *KeyManager) SigningKey() *rsa.PrivateKey {
	return km.signingKey
}

func (km *KeyManager) SigningKID() string {
	return km.signingKID
}

func (km *KeyManager) EncryptionKey() []byte {
	return km.encKey
}

func generateKID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating KID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

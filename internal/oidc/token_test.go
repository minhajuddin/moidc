package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateAndVerifyIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	claims := &TokenClaims{
		Issuer:   "http://localhost:8080",
		Subject:  "user@example.com",
		Audience: "test-client",
		Nonce:    "abc123",
		Email:    "user@example.com",
		Extra:    map[string]interface{}{"name": "Test User"},
	}

	tokenStr, err := CreateIDToken(key, "kid-1", claims, time.Hour)
	if err != nil {
		t.Fatalf("CreateIDToken failed: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	mapClaims := token.Claims.(jwt.MapClaims)
	if mapClaims["sub"] != "user@example.com" {
		t.Errorf("expected sub=user@example.com, got %v", mapClaims["sub"])
	}
	if mapClaims["name"] != "Test User" {
		t.Errorf("expected name=Test User, got %v", mapClaims["name"])
	}
	if mapClaims["nonce"] != "abc123" {
		t.Errorf("expected nonce=abc123, got %v", mapClaims["nonce"])
	}
}

func TestCreateAndDecryptAccessToken(t *testing.T) {
	encKey := make([]byte, 32)
	rand.Read(encKey)

	claims := &TokenClaims{
		Issuer:   "http://localhost:8080",
		Subject:  "user@example.com",
		Audience: "test-client",
		Email:    "user@example.com",
		Extra:    map[string]interface{}{"role": "admin"},
	}

	tokenStr, err := CreateAccessToken(encKey, claims, time.Hour)
	if err != nil {
		t.Fatalf("CreateAccessToken failed: %v", err)
	}

	decrypted, err := DecryptAccessToken(encKey, tokenStr)
	if err != nil {
		t.Fatalf("DecryptAccessToken failed: %v", err)
	}

	if decrypted["sub"] != "user@example.com" {
		t.Errorf("expected sub=user@example.com, got %v", decrypted["sub"])
	}
	if decrypted["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", decrypted["role"])
	}
}

func TestDecryptAccessToken_WrongKey(t *testing.T) {
	encKey := make([]byte, 32)
	rand.Read(encKey)

	claims := &TokenClaims{
		Issuer:  "http://localhost:8080",
		Subject: "user@example.com",
	}

	tokenStr, err := CreateAccessToken(encKey, claims, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	_, err = DecryptAccessToken(wrongKey, tokenStr)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

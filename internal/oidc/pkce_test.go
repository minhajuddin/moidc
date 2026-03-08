package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Fatalf("expected valid PKCE, got error: %v", err)
	}

	if err := VerifyPKCE("wrong-verifier", challenge, "S256"); err == nil {
		t.Fatal("expected PKCE verification to fail with wrong verifier")
	}

	if err := VerifyPKCE(verifier, challenge, "plain"); err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

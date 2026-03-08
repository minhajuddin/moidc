package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func VerifyPKCE(codeVerifier, codeChallenge, method string) error {
	if method != "S256" {
		return fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if computed != codeChallenge {
		return fmt.Errorf("PKCE verification failed")
	}
	return nil
}

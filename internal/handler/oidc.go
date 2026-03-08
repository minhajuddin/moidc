package handler

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"

	"github.com/minhajuddin/moidc/internal/oidc"
)

type OIDCHandler struct {
	baseURL    string
	keyManager *oidc.KeyManager
}

func NewOIDCHandler(baseURL string, keyManager *oidc.KeyManager) *OIDCHandler {
	return &OIDCHandler{baseURL: baseURL, keyManager: keyManager}
}

func (h *OIDCHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := oidc.NewDiscoveryDocument(h.baseURL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	pub := h.keyManager.SigningKey().Public().(*rsa.PublicKey)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.keyManager.SigningKID(),
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="moidc"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token","error_description":"Missing or invalid Authorization header"}`))
		return
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")

	claims, err := oidc.DecryptAccessToken(h.keyManager.EncryptionKey(), tokenStr)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="moidc", error="invalid_token"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token","error_description":"Token is invalid or expired"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

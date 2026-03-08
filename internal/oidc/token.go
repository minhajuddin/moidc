package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Issuer      string
	Subject     string
	Audience    string
	Nonce       string
	Email       string
	AuthTime    time.Time
	AccessToken string // set before creating ID token, used to compute at_hash
	Extra       map[string]interface{}
}

func CreateIDToken(key *rsa.PrivateKey, kid string, claims *TokenClaims, expiry time.Duration) (string, error) {
	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"exp": jwt.NewNumericDate(now.Add(expiry)),
		"iat": jwt.NewNumericDate(now),
	}
	if claims.Nonce != "" {
		mapClaims["nonce"] = claims.Nonce
	}
	if claims.Email != "" {
		mapClaims["email"] = claims.Email
	}
	if !claims.AuthTime.IsZero() {
		mapClaims["auth_time"] = claims.AuthTime.Unix()
	}
	if claims.AccessToken != "" {
		mapClaims["at_hash"] = computeAtHash(claims.AccessToken)
	}
	for k, v := range claims.Extra {
		if _, reserved := reservedClaims[k]; !reserved {
			mapClaims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func CreateAccessToken(encKey []byte, claims *TokenClaims, expiry time.Duration) (string, error) {
	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"exp": jwt.NewNumericDate(now.Add(expiry)),
		"iat": jwt.NewNumericDate(now),
	}
	if claims.Email != "" {
		mapClaims["email"] = claims.Email
	}
	for k, v := range claims.Extra {
		if _, reserved := reservedClaims[k]; !reserved {
			mapClaims[k] = v
		}
	}

	inner := jwt.NewWithClaims(jwt.SigningMethodNone, mapClaims)
	payload, err := inner.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return "", fmt.Errorf("creating inner token: %w", err)
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: encKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("creating encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("encrypting token: %w", err)
	}

	return jwe.CompactSerialize()
}

func DecryptAccessToken(encKey []byte, tokenStr string) (jwt.MapClaims, error) {
	jwe, err := jose.ParseEncrypted(tokenStr, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parsing JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting JWE: %w", err)
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"none"}))
	token, _, err := parser.ParseUnverified(string(plaintext), jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing inner JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("getting expiration: %w", err)
	}
	if exp != nil && exp.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true,
	"iat": true, "nonce": true, "email": true, "auth_time": true, "at_hash": true,
}

func computeAtHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:16]) // left half of SHA-256
}

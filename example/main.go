package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/minhajuddin/moidc/example/templates"
)

type ClientConfig struct {
	ClientName   string   `json:"client_name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Email        string   `json:"email"`
	RedirectURIs []string `json:"redirect_uris"`
}

type SessionClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername  string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

type OIDCState struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
}

var (
	config    ClientConfig
	moidcURL  string
	jwtSecret []byte
)

func main() {
	moidcURL = envOr("MOIDC_URL", "http://localhost:8080")
	listenAddr := envOr("LISTEN_ADDR", ":8081")
	envPath := envOr("ENV_JSON", "env.json")

	data, err := os.ReadFile(envPath)
	if err != nil {
		log.Fatalf("Failed to read %s: %v\nRegister a client at %s/clients/register and download the credentials JSON.", envPath, err, moidcURL)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse %s: %v", envPath, err)
	}

	jwtSecret = make([]byte, 32)
	if _, err := rand.Read(jwtSecret); err != nil {
		log.Fatalf("Failed to generate JWT secret: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleHome)
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("GET /callback", handleCallback)
	mux.HandleFunc("GET /logout", handleLogout)

	log.Printf("Example app listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		templates.Home(nil).Render(r.Context(), w)
		return
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		return jwtSecret, nil
	})
	if err != nil {
		templates.Home(nil).Render(r.Context(), w)
		return
	}

	claims := token.Claims.(*SessionClaims)
	user := &templates.UserData{
		Sub:               claims.Subject,
		Email:             claims.Email,
		Name:              claims.Name,
		GivenName:         claims.GivenName,
		FamilyName:        claims.FamilyName,
		PreferredUsername:  claims.PreferredUsername,
		Picture:           claims.Picture,
	}
	templates.Home(user).Render(r.Context(), w)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifierBytes := make([]byte, 32)
	rand.Read(verifierBytes)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	oidcState := OIDCState{State: state, CodeVerifier: codeVerifier}
	stateJSON, _ := json.Marshal(oidcState)

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    base64.RawURLEncoding.EncodeToString(stateJSON),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   300,
	})

	redirectURI := config.RedirectURIs[0]
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
		moidcURL, config.ClientID, url.QueryEscape(redirectURI), state, codeChallenge)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("OIDC error: %s - %s", errMsg, r.URL.Query().Get("error_description")), http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("oidc_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	stateJSON, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid state cookie", http.StatusBadRequest)
		return
	}

	var oidcState OIDCState
	if err := json.Unmarshal(stateJSON, &oidcState); err != nil {
		http.Error(w, "Invalid state cookie", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != oidcState.State {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   -1,
	})

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	redirectURI := config.RedirectURIs[0]

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"code_verifier": {oidcState.CodeVerifier},
	}

	resp, err := http.Post(moidcURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Token exchange failed (status %d): %s", resp.StatusCode, body), http.StatusInternalServerError)
		return
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	idToken, ok := tokenResp["id_token"].(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}

	// Decode id_token payload (no signature verification - we trust our own provider over TLS)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		http.Error(w, "Invalid id_token format", http.StatusInternalServerError)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "Failed to decode id_token", http.StatusInternalServerError)
		return
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		http.Error(w, "Failed to parse id_token claims", http.StatusInternalServerError)
		return
	}

	// Create session JWT
	now := time.Now()
	sessionClaims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claimStr(claims, "sub"),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
		Email:             claimStr(claims, "email"),
		Name:              claimStr(claims, "name"),
		GivenName:         claimStr(claims, "given_name"),
		FamilyName:        claimStr(claims, "family_name"),
		PreferredUsername:  claimStr(claims, "preferred_username"),
		Picture:           claimStr(claims, "picture"),
	}

	sessionToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims)
	signed, err := sessionToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    signed,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   86400,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func claimStr(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

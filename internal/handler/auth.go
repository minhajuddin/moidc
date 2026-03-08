package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/internal/oidc"
	"github.com/minhajuddin/moidc/templates"
)

const defaultTOML = `name = "Jane Doe"
given_name = "Jane"
family_name = "Doe"
preferred_username = "janedoe"
picture = "https://i.pravatar.cc/300"
`

type AuthHandler struct {
	db         *db.DB
	keyManager *oidc.KeyManager
	baseURL    string
}

func NewAuthHandler(database *db.DB, keyManager *oidc.KeyManager, baseURL string) *AuthHandler {
	return &AuthHandler{db: database, keyManager: keyManager, baseURL: baseURL}
}

func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if responseType != "code" {
		renderError(w, r, "Invalid Request", "response_type must be 'code'.", http.StatusBadRequest)
		return
	}

	client, err := h.db.GetClient(clientID)
	if err != nil {
		renderError(w, r, "Invalid Client", "Unknown client_id.", http.StatusBadRequest)
		return
	}

	if !isValidRedirectURI(client.RedirectURIs, redirectURI) {
		renderError(w, r, "Invalid Request", "Invalid redirect_uri.", http.StatusBadRequest)
		return
	}

	templates.Login(
		client.ClientName, clientID, redirectURI, scope, state, nonce,
		codeChallenge, codeChallengeMethod,
	).Render(r.Context(), w)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, r, "Bad Request", "Could not parse form.", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	if email == "" {
		renderError(w, r, "Validation Error", "Email is required.", http.StatusBadRequest)
		return
	}

	client, err := h.db.GetClient(clientID)
	if err != nil {
		renderError(w, r, "Invalid Client", "Unknown client_id.", http.StatusBadRequest)
		return
	}

	templates.Consent(
		client.ClientName, clientID, email, redirectURI, scope, state, nonce,
		codeChallenge, codeChallengeMethod, defaultTOML,
	).Render(r.Context(), w)
}

func (h *AuthHandler) Consent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, r, "Bad Request", "Could not parse form.", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	clientID := r.FormValue("client_id")
	email := r.FormValue("email")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	profileTOML := r.FormValue("profile_toml")

	if action == "deny" {
		redirectWithError(w, r, redirectURI, state, "access_denied", "User denied the request")
		return
	}

	client, err := h.db.GetClient(clientID)
	if err != nil {
		renderError(w, r, "Invalid Client", "Unknown client_id.", http.StatusBadRequest)
		return
	}

	if !isValidRedirectURI(client.RedirectURIs, redirectURI) {
		renderError(w, r, "Invalid Request", "Invalid redirect_uri.", http.StatusBadRequest)
		return
	}

	// Validate TOML claims
	if profileTOML != "" {
		if _, err := oidc.ParseTOMLClaims(profileTOML); err != nil {
			renderError(w, r, "Invalid Claims", fmt.Sprintf("TOML error: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Generate authorization code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		renderError(w, r, "Server Error", "Could not generate code.", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	codeHash := sha256Hex(code)

	authCode := &db.AuthCode{
		CodeHash:            codeHash,
		ClientID:            clientID,
		Email:               email,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ProfileSnapshot:     profileTOML,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := h.db.CreateAuthCode(authCode); err != nil {
		renderError(w, r, "Server Error", "Could not store authorization code.", http.StatusInternalServerError)
		return
	}

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "Could not parse form.", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		tokenError(w, "unsupported_grant_type", "Only authorization_code is supported.", http.StatusBadRequest)
		return
	}

	// Authenticate client
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		tokenError(w, "invalid_client", "Client authentication failed.", http.StatusUnauthorized)
		return
	}

	if _, err := h.db.ValidateClientSecret(clientID, clientSecret); err != nil {
		tokenError(w, "invalid_client", "Client authentication failed.", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	codeHash := sha256Hex(code)
	authCode, err := h.db.GetAuthCode(codeHash)
	if err != nil {
		tokenError(w, "invalid_grant", "Invalid authorization code.", http.StatusBadRequest)
		return
	}

	if authCode.UsedAt != nil {
		tokenError(w, "invalid_grant", "Authorization code already used.", http.StatusBadRequest)
		return
	}
	if time.Now().After(authCode.ExpiresAt) {
		tokenError(w, "invalid_grant", "Authorization code expired.", http.StatusBadRequest)
		return
	}
	if authCode.ClientID != clientID {
		tokenError(w, "invalid_grant", "Client ID mismatch.", http.StatusBadRequest)
		return
	}
	if authCode.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "Redirect URI mismatch.", http.StatusBadRequest)
		return
	}

	// PKCE verification
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			tokenError(w, "invalid_grant", "code_verifier required.", http.StatusBadRequest)
			return
		}
		if err := oidc.VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			tokenError(w, "invalid_grant", "PKCE verification failed.", http.StatusBadRequest)
			return
		}
	}

	// Mark code as used
	if err := h.db.MarkAuthCodeUsed(codeHash); err != nil {
		tokenError(w, "server_error", "Could not mark code as used.", http.StatusInternalServerError)
		return
	}

	// Parse profile claims
	var extraClaims map[string]interface{}
	if authCode.ProfileSnapshot != "" {
		extraClaims, err = oidc.ParseTOMLClaims(authCode.ProfileSnapshot)
		if err != nil {
			tokenError(w, "server_error", "Could not parse profile claims.", http.StatusInternalServerError)
			return
		}
	}

	tokenClaims := &oidc.TokenClaims{
		Issuer:   h.baseURL,
		Subject:  authCode.Email,
		Audience: clientID,
		Nonce:    authCode.Nonce,
		Email:    authCode.Email,
		Extra:    extraClaims,
	}

	idTokenExpiry := 1 * time.Hour
	accessTokenExpiry := 1 * time.Hour

	idToken, err := oidc.CreateIDToken(h.keyManager.SigningKey(), h.keyManager.SigningKID(), tokenClaims, idTokenExpiry)
	if err != nil {
		tokenError(w, "server_error", "Could not create ID token.", http.StatusInternalServerError)
		return
	}

	accessToken, err := oidc.CreateAccessToken(h.keyManager.EncryptionKey(), tokenClaims, accessTokenExpiry)
	if err != nil {
		tokenError(w, "server_error", "Could not create access token.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":%d,"id_token":%q}`,
		accessToken, int(accessTokenExpiry.Seconds()), idToken)
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try Basic auth first
	if user, pass, hasBasic := r.BasicAuth(); hasBasic {
		return user, pass, true
	}
	// Fall back to POST body
	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")
	if clientID != "" && clientSecret != "" {
		return clientID, clientSecret, true
	}
	return "", "", false
}

func isValidRedirectURI(allowed []string, uri string) bool {
	for _, a := range allowed {
		if a == uri {
			return true
		}
	}
	return false
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", errDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func tokenError(w http.ResponseWriter, errCode, errDesc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, errCode, errDesc)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

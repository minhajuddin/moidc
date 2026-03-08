package moidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	moidc "github.com/minhajuddin/moidc"
	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/internal/oidc"
	"github.com/minhajuddin/moidc/internal/server"
)

func setupTestServer(t *testing.T) (*httptest.Server, *db.DB) {
	t.Helper()

	migrationsDir, err := fs.Sub(moidc.MigrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.Open(dbPath, migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	keyManager, err := oidc.NewKeyManager(database)
	if err != nil {
		t.Fatal(err)
	}

	// Use a placeholder, will be set after server starts
	srv := server.New(database, keyManager, "PLACEHOLDER")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// Recreate with proper base URL
	srv2 := server.New(database, keyManager, ts.URL)
	ts.Config.Handler = srv2

	return ts, database
}

func TestFullOIDCFlow(t *testing.T) {
	ts, database := setupTestServer(t)
	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	}

	// Step 1: Register a client
	redirectURI := "http://localhost:9999/callback"
	err := database.CreateClient("test_client_id", "test_client_secret", "Test App", "dev@test.com", []string{redirectURI})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// Step 2: Generate PKCE
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Step 3: Start authorization
	authURL := ts.URL + "/authorize?response_type=code&client_id=test_client_id&redirect_uri=" +
		url.QueryEscape(redirectURI) + "&scope=openid+profile+email&state=teststate&nonce=testnonce" +
		"&code_challenge=" + codeChallenge + "&code_challenge_method=S256"

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /authorize, got %d", resp.StatusCode)
	}

	// Step 4: Login (POST email)
	loginData := url.Values{
		"email":                 {"user@example.com"},
		"client_id":             {"test_client_id"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"teststate"},
		"nonce":                 {"testnonce"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	resp, err = client.PostForm(ts.URL+"/authorize/login", loginData)
	if err != nil {
		t.Fatalf("POST /authorize/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /authorize/login, got %d", resp.StatusCode)
	}

	// Step 5: Consent
	consentData := url.Values{
		"action":                {"approve"},
		"client_id":             {"test_client_id"},
		"email":                 {"user@example.com"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"teststate"},
		"nonce":                 {"testnonce"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"profile_toml":          {"name = \"Jane Doe\"\nrole = \"admin\""},
	}
	resp, err = client.PostForm(ts.URL+"/authorize/consent", consentData)
	if err != nil {
		t.Fatalf("POST /authorize/consent: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 302 {
		t.Fatalf("expected 302 from /authorize/consent, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parsing redirect location: %v", err)
	}

	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	if redirectURL.Query().Get("state") != "teststate" {
		t.Fatal("state mismatch in redirect")
	}

	// Step 6: Token exchange
	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"test_client_id"},
		"client_secret": {"test_client_secret"},
		"code_verifier": {codeVerifier},
	}
	resp, err = client.PostForm(ts.URL+"/token", tokenData)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /token, got %d: %s", resp.StatusCode, body)
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		t.Fatalf("parsing token response: %v", err)
	}

	if tokenResp["access_token"] == nil {
		t.Fatal("no access_token in response")
	}
	if tokenResp["id_token"] == nil {
		t.Fatal("no id_token in response")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", tokenResp["token_type"])
	}

	// Step 7: Verify ID token claims
	idToken := tokenResp["id_token"].(string)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding JWT payload: %v", err)
	}
	var idClaims map[string]interface{}
	json.Unmarshal(payload, &idClaims)

	if idClaims["sub"] != "user@example.com" {
		t.Errorf("expected sub=user@example.com, got %v", idClaims["sub"])
	}
	if idClaims["name"] != "Jane Doe" {
		t.Errorf("expected name=Jane Doe, got %v", idClaims["name"])
	}
	if idClaims["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", idClaims["role"])
	}
	if idClaims["nonce"] != "testnonce" {
		t.Errorf("expected nonce=testnonce, got %v", idClaims["nonce"])
	}

	// Step 8: UserInfo
	accessToken := tokenResp["access_token"].(string)
	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /userinfo, got %d: %s", resp.StatusCode, body)
	}

	var userInfo map[string]interface{}
	json.Unmarshal(body, &userInfo)
	if userInfo["sub"] != "user@example.com" {
		t.Errorf("userinfo sub mismatch: %v", userInfo["sub"])
	}
	if userInfo["email"] != "user@example.com" {
		t.Errorf("userinfo email mismatch: %v", userInfo["email"])
	}
}

func TestDiscoveryEndpoint(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var doc map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&doc)

	if doc["issuer"] != ts.URL {
		t.Errorf("expected issuer=%s, got %v", ts.URL, doc["issuer"])
	}
	if doc["authorization_endpoint"] != ts.URL+"/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", doc["authorization_endpoint"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jwks)

	keys := jwks["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", key["alg"])
	}
}


package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	moidcURL     = envOr("MOIDC_URL", "http://localhost:8080")
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	callbackAddr = envOr("CALLBACK_ADDR", ":8081")
	callbackURL  = envOr("CALLBACK_URL", "http://localhost:8081/callback")
)

func main() {
	if clientID == "" || clientSecret == "" {
		log.Fatal("CLIENT_ID and CLIENT_SECRET env vars are required.\n" +
			"Register a client at " + moidcURL + "/clients/register first.")
	}

	// Generate PKCE
	verifierBytes := make([]byte, 32)
	for i := range verifierBytes {
		verifierBytes[i] = byte(rand.Intn(256))
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	state := randomString(16)

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
		moidcURL, clientID, url.QueryEscape(callbackURL), state, codeChallenge)

	fmt.Println("Open this URL in your browser:")
	fmt.Println(authURL)
	fmt.Println()

	codeCh := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("error") != "" {
			fmt.Fprintf(w, "Error: %s - %s", r.URL.Query().Get("error"), r.URL.Query().Get("error_description"))
			return
		}
		if r.URL.Query().Get("state") != state {
			fmt.Fprintf(w, "State mismatch!")
			return
		}
		code := r.URL.Query().Get("code")
		fmt.Fprintf(w, "Authorization code received! Check your terminal.")
		codeCh <- code
	})

	go func() {
		log.Printf("Callback server listening on %s", callbackAddr)
		http.ListenAndServe(callbackAddr, mux)
	}()

	code := <-codeCh
	fmt.Printf("\nReceived authorization code: %s\n\n", code[:20]+"...")

	// Exchange code for tokens
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {codeVerifier},
	}

	resp, err := http.Post(moidcURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("Token request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Token response (status %d):\n", resp.StatusCode)

	var tokenResp map[string]interface{}
	json.Unmarshal(body, &tokenResp)
	pretty, _ := json.MarshalIndent(tokenResp, "", "  ")
	fmt.Println(string(pretty))

	// Decode ID token (just the payload, no verification)
	if idToken, ok := tokenResp["id_token"].(string); ok {
		parts := strings.Split(idToken, ".")
		if len(parts) == 3 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var claims map[string]interface{}
				json.Unmarshal(payload, &claims)
				pretty, _ := json.MarshalIndent(claims, "", "  ")
				fmt.Printf("\nDecoded ID Token claims:\n%s\n", string(pretty))
			}
		}
	}

	// Call userinfo
	if accessToken, ok := tokenResp["access_token"].(string); ok {
		req, _ := http.NewRequest("GET", moidcURL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("UserInfo request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var userInfo map[string]interface{}
		json.Unmarshal(body, &userInfo)
		pretty, _ := json.MarshalIndent(userInfo, "", "  ")
		fmt.Printf("\nUserInfo response:\n%s\n", string(pretty))
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

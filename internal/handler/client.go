package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/templates"
)

type ClientHandler struct {
	db *db.DB
}

func NewClientHandler(database *db.DB) *ClientHandler {
	return &ClientHandler{db: database}
}

func (h *ClientHandler) RegisterForm(w http.ResponseWriter, r *http.Request) {
	templates.ClientRegister().Render(r.Context(), w)
}

func (h *ClientHandler) Register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, r, "Bad Request", "Could not parse form data.", http.StatusBadRequest)
		return
	}

	clientName := strings.TrimSpace(r.FormValue("client_name"))
	email := strings.TrimSpace(r.FormValue("email"))
	redirectURIsRaw := strings.TrimSpace(r.FormValue("redirect_uris"))

	if clientName == "" || email == "" || redirectURIsRaw == "" {
		renderError(w, r, "Validation Error", "All fields are required.", http.StatusBadRequest)
		return
	}

	if len(clientName) > 255 {
		renderError(w, r, "Validation Error", "Client name is too long (max 255 characters).", http.StatusBadRequest)
		return
	}

	var redirectURIs []string
	for _, uri := range strings.Split(redirectURIsRaw, "\n") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			parsed, err := url.Parse(uri)
			if err != nil {
				renderError(w, r, "Validation Error", "Invalid redirect URI: "+uri, http.StatusBadRequest)
				return
			}
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")) {
				renderError(w, r, "Validation Error", "Redirect URIs must use https (or http://localhost for development).", http.StatusBadRequest)
				return
			}
			redirectURIs = append(redirectURIs, uri)
		}
	}
	if len(redirectURIs) == 0 {
		renderError(w, r, "Validation Error", "At least one redirect URI is required.", http.StatusBadRequest)
		return
	}

	clientID, err := randomHex(24)
	if err != nil {
		renderError(w, r, "Server Error", "Could not generate client credentials.", http.StatusInternalServerError)
		return
	}
	clientSecret, err := randomHex(48)
	if err != nil {
		renderError(w, r, "Server Error", "Could not generate client credentials.", http.StatusInternalServerError)
		return
	}
	clientID = "moidc_" + clientID
	clientSecret = "moidcs_" + clientSecret

	if err := h.db.CreateClient(clientID, clientSecret, clientName, email, redirectURIs); err != nil {
		slog.Error("failed to create client", "error", err)
		renderError(w, r, "Server Error", "Could not create client.", http.StatusInternalServerError)
		return
	}

	slog.Info("client registered", "client_id", clientID, "client_name", clientName)
	templates.ClientCreated(clientName, clientID, clientSecret, email, redirectURIs).Render(r.Context(), w)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func renderError(w http.ResponseWriter, r *http.Request, title, message string, status int) {
	w.WriteHeader(status)
	templates.Error(title, message).Render(r.Context(), w)
}

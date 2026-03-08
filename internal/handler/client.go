package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
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

	var redirectURIs []string
	for _, uri := range strings.Split(redirectURIsRaw, "\n") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			redirectURIs = append(redirectURIs, uri)
		}
	}
	if len(redirectURIs) == 0 {
		renderError(w, r, "Validation Error", "At least one redirect URI is required.", http.StatusBadRequest)
		return
	}

	clientID := "moidc_" + randomHex(24)
	clientSecret := "moidcs_" + randomHex(48)

	if err := h.db.CreateClient(clientID, clientSecret, clientName, email, redirectURIs); err != nil {
		renderError(w, r, "Server Error", "Could not create client.", http.StatusInternalServerError)
		return
	}

	templates.ClientCreated(clientName, clientID, clientSecret).Render(r.Context(), w)
}

func randomHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func renderError(w http.ResponseWriter, r *http.Request, title, message string, status int) {
	w.WriteHeader(status)
	templates.Error(title, message).Render(r.Context(), w)
}

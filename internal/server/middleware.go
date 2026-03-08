package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline'")

		path := r.URL.Path
		if path == "/token" || strings.HasPrefix(path, "/authorize") {
			w.Header().Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

const csrfCookieName = "_csrf"
const csrfFormField = "_csrf"

func csrfProtect(baseURL string) func(http.Handler) http.Handler {
	secure := strings.HasPrefix(baseURL, "https://")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				// Set CSRF cookie if not present
				if _, err := r.Cookie(csrfCookieName); err != nil {
					token, err := generateCSRFToken()
					if err != nil {
						slog.Error("failed to generate CSRF token", "error", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					http.SetCookie(w, &http.Cookie{
						Name:     csrfCookieName,
						Value:    token,
						Path:     "/",
						HttpOnly: true,
						Secure:   secure,
						SameSite: http.SameSiteStrictMode,
					})
				}
				// Wrap response writer to inject CSRF hidden fields into forms
				cw := &csrfResponseWriter{ResponseWriter: w, r: r}
				next.ServeHTTP(cw, r)
				return
			}

			if r.Method == http.MethodPost {
				cookie, err := r.Cookie(csrfCookieName)
				if err != nil || cookie.Value == "" {
					http.Error(w, "Forbidden: missing CSRF token", http.StatusForbidden)
					return
				}
				if err := r.ParseForm(); err != nil {
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}
				formToken := r.FormValue(csrfFormField)
				if formToken == "" || formToken != cookie.Value {
					http.Error(w, "Forbidden: CSRF token mismatch", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type csrfResponseWriter struct {
	http.ResponseWriter
	r *http.Request
}

func (w *csrfResponseWriter) Write(b []byte) (int, error) {
	token := ""
	if cookie, err := w.r.Cookie(csrfCookieName); err == nil {
		token = cookie.Value
	} else {
		// Token was just set in the response cookie, extract it
		for _, c := range w.ResponseWriter.Header()["Set-Cookie"] {
			if strings.HasPrefix(c, csrfCookieName+"=") {
				parts := strings.SplitN(c, "=", 2)
				if len(parts) == 2 {
					token = strings.SplitN(parts[1], ";", 2)[0]
				}
			}
		}
	}

	if token != "" {
		content := string(b)
		hiddenField := `<input type="hidden" name="` + csrfFormField + `" value="` + token + `">`
		content = strings.ReplaceAll(content, "</form>", hiddenField+"</form>")
		return w.ResponseWriter.Write([]byte(content))
	}
	return w.ResponseWriter.Write(b)
}

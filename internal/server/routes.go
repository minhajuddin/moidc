package server

import (
	"net/http"

	"github.com/minhajuddin/moidc/templates"
)

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	templates.Home(s.baseURL).Render(r.Context(), w)
}

package server

import (
	"net/http"

	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/internal/handler"
	"github.com/minhajuddin/moidc/internal/oidc"
)

type Server struct {
	mux        *http.ServeMux
	db         *db.DB
	keyManager *oidc.KeyManager
	baseURL    string
}

func New(database *db.DB, keyManager *oidc.KeyManager, baseURL string) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		db:         database,
		keyManager: keyManager,
		baseURL:    baseURL,
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	oidcH := handler.NewOIDCHandler(s.baseURL, s.keyManager)
	clientH := handler.NewClientHandler(s.db)
	authH := handler.NewAuthHandler(s.db, s.keyManager, s.baseURL)

	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.HandleFunc("GET /clients/register", clientH.RegisterForm)
	s.mux.HandleFunc("POST /clients/register", clientH.Register)
	s.mux.HandleFunc("GET /.well-known/openid-configuration", oidcH.Discovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", oidcH.JWKS)
	s.mux.HandleFunc("GET /authorize", authH.Authorize)
	s.mux.HandleFunc("POST /authorize/login", authH.Login)
	s.mux.HandleFunc("POST /authorize/consent", authH.Consent)
	s.mux.HandleFunc("POST /token", authH.Token)
	s.mux.HandleFunc("GET /userinfo", oidcH.UserInfo)
	s.mux.HandleFunc("POST /userinfo", oidcH.UserInfo)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}

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
	handler    http.Handler
}

func New(database *db.DB, keyManager *oidc.KeyManager, baseURL string) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		db:         database,
		keyManager: keyManager,
		baseURL:    baseURL,
	}
	s.routes()
	s.handler = securityHeaders(s.mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() {
	oidcH := handler.NewOIDCHandler(s.baseURL, s.keyManager)
	clientH := handler.NewClientHandler(s.db)
	authH := handler.NewAuthHandler(s.db, s.keyManager, s.baseURL)

	csrf := func(h http.HandlerFunc) http.Handler {
		return csrfProtect(http.HandlerFunc(h))
	}

	rl := newRateLimiter()
	rateLimit := rateLimitMiddleware(rl)

	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.Handle("GET /clients/register", csrf(clientH.RegisterForm))
	s.mux.Handle("POST /clients/register", rateLimit(csrf(clientH.Register)))
	s.mux.HandleFunc("GET /.well-known/openid-configuration", oidcH.Discovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", oidcH.JWKS)
	s.mux.Handle("GET /authorize", csrf(authH.Authorize))
	s.mux.Handle("POST /authorize/login", rateLimit(csrf(authH.Login)))
	s.mux.Handle("POST /authorize/consent", csrf(authH.Consent))
	s.mux.Handle("POST /token", rateLimit(http.HandlerFunc(authH.Token)))
	s.mux.HandleFunc("GET /userinfo", oidcH.UserInfo)
	s.mux.HandleFunc("POST /userinfo", oidcH.UserInfo)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}

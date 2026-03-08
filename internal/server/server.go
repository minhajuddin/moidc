package server

import (
	"io/fs"
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

func New(database *db.DB, keyManager *oidc.KeyManager, baseURL string, staticFS fs.FS) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		db:         database,
		keyManager: keyManager,
		baseURL:    baseURL,
	}
	s.routes(staticFS)
	s.handler = securityHeaders(s.mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes(staticFS fs.FS) {
	oidcH := handler.NewOIDCHandler(s.baseURL, s.keyManager)
	clientH := handler.NewClientHandler(s.db)
	authH := handler.NewAuthHandler(s.db, s.keyManager, s.baseURL)

	csrf := csrfProtect(s.baseURL)
	wrapCSRF := func(h http.HandlerFunc) http.Handler {
		return csrf(http.HandlerFunc(h))
	}

	rl := newRateLimiter()
	rateLimit := rateLimitMiddleware(rl)

	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.Handle("GET /clients/register", wrapCSRF(clientH.RegisterForm))
	s.mux.Handle("POST /clients/register", rateLimit(wrapCSRF(clientH.Register)))
	s.mux.HandleFunc("GET /.well-known/openid-configuration", oidcH.Discovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", oidcH.JWKS)
	s.mux.Handle("GET /authorize", wrapCSRF(authH.Authorize))
	s.mux.Handle("POST /authorize/login", rateLimit(wrapCSRF(authH.Login)))
	s.mux.Handle("POST /authorize/consent", wrapCSRF(authH.Consent))
	s.mux.Handle("POST /token", rateLimit(http.HandlerFunc(authH.Token)))
	s.mux.Handle("GET /userinfo", rateLimit(http.HandlerFunc(oidcH.UserInfo)))
	s.mux.Handle("POST /userinfo", rateLimit(http.HandlerFunc(oidcH.UserInfo)))
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
}

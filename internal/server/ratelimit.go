package server

import (
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
	}
	go rl.cleanup()
	return rl
}

const (
	rateLimit      = 10.0 // requests per second
	rateBurst      = 20   // max burst
	cleanupAge     = 3 * time.Minute
	maxVisitors    = 10000
)

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	now := time.Now()
	if !exists {
		// Fail-open: skip rate limiting for new IPs when map is full
		if len(rl.visitors) >= maxVisitors {
			return true
		}
		rl.visitors[ip] = &visitor{tokens: rateBurst - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(v.lastSeen).Seconds()
	v.lastSeen = now
	v.tokens += elapsed * rateLimit
	if v.tokens > rateBurst {
		v.tokens = rateBurst
	}
	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > cleanupAge {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

var trustProxy = os.Getenv("MOIDC_TRUST_PROXY") != ""

func rateLimitMiddleware(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if trustProxy {
				if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
					ip = fwd
				}
			}
			if !rl.allow(ip) {
				slog.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
				http.Error(w, `{"error":"rate_limit_exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

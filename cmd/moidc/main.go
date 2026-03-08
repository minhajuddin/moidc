package main

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	moidc "github.com/minhajuddin/moidc"
	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/internal/oidc"
	"github.com/minhajuddin/moidc/internal/server"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	addr := envOr("MOIDC_ADDR", ":8080")
	baseURL := envOr("MOIDC_BASE_URL", "http://localhost:8080")
	dbPath := envOr("MOIDC_DB_PATH", "moidc.db")

	migrationsDir, err := fs.Sub(moidc.MigrationsFS, "migrations")
	if err != nil {
		slog.Error("failed to get migrations sub-fs", "error", err)
		os.Exit(1)
	}

	database, err := db.Open(dbPath, migrationsDir)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	keyManager, err := oidc.NewKeyManager(database)
	if err != nil {
		slog.Error("failed to initialize key manager", "error", err)
		os.Exit(1)
	}

	staticFS, err := fs.Sub(moidc.StaticFS, "static")
	if err != nil {
		slog.Error("failed to get static sub-fs", "error", err)
		os.Exit(1)
	}

	// Start expired auth code cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if n, err := database.CleanupExpiredCodes(ctx); err != nil {
					slog.Error("auth code cleanup failed", "error", err)
				} else if n > 0 {
					slog.Info("cleaned up expired auth codes", "count", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	srv := server.New(database, keyManager, baseURL, staticFS)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig.String())
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
	}()

	slog.Info("moidc starting", "addr", addr, "base_url", baseURL)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

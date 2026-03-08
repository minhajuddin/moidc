package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"

	moidc "github.com/minhajuddin/moidc"
	"github.com/minhajuddin/moidc/internal/db"
	"github.com/minhajuddin/moidc/internal/oidc"
	"github.com/minhajuddin/moidc/internal/server"
)

func main() {
	addr := envOr("MOIDC_ADDR", ":8080")
	baseURL := envOr("MOIDC_BASE_URL", "http://localhost:8080")
	dbPath := envOr("MOIDC_DB_PATH", "moidc.db")

	migrationsDir, err := fs.Sub(moidc.MigrationsFS, "migrations")
	if err != nil {
		log.Fatalf("Failed to get migrations sub-fs: %v", err)
	}

	database, err := db.Open(dbPath, migrationsDir)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	keyManager, err := oidc.NewKeyManager(database)
	if err != nil {
		log.Fatalf("Failed to initialize key manager: %v", err)
	}

	srv := server.New(database, keyManager, baseURL)

	log.Printf("moidc starting on %s (base URL: %s)", addr, baseURL)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

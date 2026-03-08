# moidc

A minimal OpenID Connect (OIDC) provider built with Go. It implements the core OIDC Authorization Code flow with PKCE support, backed by SQLite.

## Features

- **Authorization Code flow** with PKCE (S256)
- **Dynamic client registration** via a web UI
- **OIDC Discovery** (`/.well-known/openid-configuration`) and **JWKS** (`/.well-known/jwks.json`)
- **UserInfo endpoint** with standard claims (email, profile)
- RS256 token signing with automatic key management
- CSRF protection, rate limiting, and security headers
- SQLite storage with embedded migrations
- Single binary deployment

## Quick Start

### Prerequisites

- Go 1.24+
- [templ](https://templ.guide/) (`go install github.com/a-h/templ/cmd/templ@latest`)

### Setup

```sh
# Download the Tailwind CSS standalone CLI
make setup

# Generate templates and CSS, then start the server
make dev
```

The server starts at `http://localhost:8080`.

## Configuration

Configuration is done via environment variables:

| Variable | Default | Description |
|---|---|---|
| `MOIDC_ADDR` | `:8080` | Listen address |
| `MOIDC_BASE_URL` | `http://localhost:8080` | Public base URL (used as issuer) |
| `MOIDC_DB_PATH` | `moidc.db` | Path to the SQLite database file |

## Endpoints

| Path | Method | Description |
|---|---|---|
| `/` | GET | Home page |
| `/clients/register` | GET, POST | Client registration UI |
| `/.well-known/openid-configuration` | GET | OIDC Discovery document |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/authorize` | GET | Authorization endpoint |
| `/authorize/login` | POST | Login form submission |
| `/authorize/consent` | POST | Consent form submission |
| `/token` | POST | Token endpoint |
| `/userinfo` | GET, POST | UserInfo endpoint |

## Development

```sh
make setup      # Download Tailwind CSS binary
make generate   # Run templ generate + Tailwind CSS
make css        # Watch mode for Tailwind CSS
make dev        # Generate + run the server
make build      # Build the binary to bin/moidc
make test       # Run tests
```

## Project Structure

```
cmd/moidc/          Main application entry point
cmd/testclient/     Test OIDC client for development
internal/
  db/               SQLite database layer
  handler/          HTTP handlers (auth, client, OIDC)
  oidc/             OIDC logic (tokens, keys, PKCE, discovery)
  server/           Server setup, routing, middleware
templates/          templ HTML templates
migrations/         SQL migration files
static/             CSS and static assets
```

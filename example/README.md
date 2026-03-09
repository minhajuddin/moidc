# moidc Example Client

A minimal OIDC client app that demonstrates the Authorization Code + PKCE flow with [moidc](https://github.com/minhajuddin/moidc).

## Setup

1. Start moidc:
   ```
   cd /path/to/moidc && go run ./cmd/moidc
   ```

2. Register a client at `http://localhost:8080/clients/register` with redirect URI `http://localhost:8081/callback`.

3. Download the credentials JSON and save it as `env.json` in this directory.

4. Run the example app:
   ```
   templ generate && go run .
   ```

5. Open `http://localhost:8081` in your browser.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENV_JSON` | `env.json` | Path to the credentials JSON file |
| `MOIDC_URL` | `http://localhost:8080` | URL of the moidc server |
| `LISTEN_ADDR` | `:8081` | Address to listen on |

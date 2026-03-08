.PHONY: dev build generate test css

generate:
	templ generate
	npx tailwindcss -i static/input.css -o static/output.css --minify

css:
	npx tailwindcss -i static/input.css -o static/output.css --watch

dev: generate
	go run ./cmd/moidc

build: generate
	go build -o bin/moidc ./cmd/moidc

test:
	go test ./...

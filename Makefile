.PHONY: dev build generate test css setup

TAILWIND_VERSION := latest
TAILWIND_BIN := ./bin/tailwindcss

setup:
	mkdir -p bin
	curl -sLO --output-dir bin https://github.com/tailwindlabs/tailwindcss/releases/$(TAILWIND_VERSION)/download/tailwindcss-macos-arm64
	chmod +x bin/tailwindcss-macos-arm64
	mv bin/tailwindcss-macos-arm64 $(TAILWIND_BIN)

generate:
	templ generate
	./bin/tailwindcss -i static/input.css -o static/output.css --minify

css:
	./bin/tailwindcss -i static/input.css -o static/output.css --watch

dev: generate
	go run ./cmd/moidc

build: generate
	go build -o bin/moidc ./cmd/moidc

test:
	go test ./...

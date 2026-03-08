FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev nodejs npm
RUN go install github.com/a-h/templ/cmd/templ@latest

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN templ generate
RUN npm install tailwindcss && npx tailwindcss -i static/input.css -o static/output.css --minify
RUN CGO_ENABLED=1 go build -o /bin/moidc ./cmd/moidc

FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs

COPY --from=litestream/litestream:0.3 /usr/local/bin/litestream /usr/local/bin/litestream
COPY --from=builder /bin/moidc /usr/local/bin/moidc
COPY --from=builder /src/static /app/static
COPY litestream.yml /etc/litestream.yml

RUN addgroup -g 999 moidc && adduser -D -u 999 -G moidc moidc
RUN mkdir -p /data && chown moidc:moidc /data

WORKDIR /app
ENV MOIDC_DB_PATH=/data/moidc.db
EXPOSE 8080

USER moidc

HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --spider http://localhost:8080/.well-known/openid-configuration || exit 1

CMD ["litestream", "replicate", "-exec", "moidc"]

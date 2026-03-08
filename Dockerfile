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

WORKDIR /app
ENV MOIDC_DB_PATH=/data/moidc.db
EXPOSE 8080

CMD ["litestream", "replicate", "-exec", "moidc"]

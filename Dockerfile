# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /nano-pulse .

# ---- runtime stage ----
FROM scratch
# Root CAs so the ACME client can reach Let's Encrypt over TLS.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /nano-pulse /nano-pulse
# 8080 = plain HTTP (default). 80/443 = Let's Encrypt or self-signed HTTPS.
EXPOSE 8080 80 443
# Persist certs (Let's Encrypt cache or the self-signed pair) across restarts.
VOLUME ["/data"]
ENV NP_LISTEN=":8080" \
    NODE_RPC_URL="http://127.0.0.1:7076" \
    NP_POLL_INTERVAL="5s" \
    NP_TLS_CACHE="/data/certs"
ENTRYPOINT ["/nano-pulse"]

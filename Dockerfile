# Build stage
FROM golang:1.25.12-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

# Copy only what is needed to build, governed by .dockerignore.
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=docker -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /leakwatch .

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git && \
    adduser -D -h /home/leakwatch leakwatch

COPY --from=builder /leakwatch /usr/local/bin/leakwatch

USER leakwatch
WORKDIR /scan

ENTRYPOINT ["leakwatch"]
CMD ["--help"]

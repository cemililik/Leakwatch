# Build stage
FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

# Commit hash for -X main.commit=. Not read from `git rev-parse` here: .git is
# excluded from the build context by .dockerignore (so git would always
# resolve to "unknown"), and ADR-0003 keeps this image git-free otherwise.
# Pass the real short SHA explicitly, e.g.:
#   docker build --build-arg COMMIT=$(git rev-parse --short HEAD) .
ARG COMMIT=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

# Copy only what is needed to build, governed by .dockerignore.
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=docker -X main.commit=${COMMIT} -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /leakwatch .

# Runtime stage
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# ADR-0003: Leakwatch uses go-git (pure Go), so the runtime image never shells
# out to a git binary; only ca-certificates is needed for outbound TLS (e.g.
# verifier API calls).
RUN apk add --no-cache ca-certificates && \
    adduser -D -h /home/leakwatch leakwatch

COPY --from=builder /leakwatch /usr/local/bin/leakwatch

USER leakwatch
WORKDIR /scan

ENTRYPOINT ["leakwatch"]
CMD ["--help"]

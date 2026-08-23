# Build stage
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

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
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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

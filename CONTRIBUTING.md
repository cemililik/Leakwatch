# Contributing Guide

Thank you for your interest in contributing to Leakwatch!

## Development Environment

```bash
git clone https://github.com/HodeTech/Leakwatch.git
cd Leakwatch
go mod download
go test -race ./...
```

## Requirements

- Go 1.25+
- gofumpt
- golangci-lint v2+
- Git 2.30+

## Development Workflow

1. Create a feature branch from `main`: `git checkout -b feature/my-feature`
2. Make your changes
3. Run tests: `go test -race ./...`
4. Format your code: `gofumpt -w .` (mandatory — a strict superset of `gofmt`; CI rejects non-compliant formatting)
5. Run lint checks: `golangci-lint run ./... --config .golangci.yml` (must pass with 0 issues before committing)
6. Create a pull request

## Standards

Please review the following standards documents:

- [Development Standards](docs/standards/04-DEVELOPMENT-STANDARDS.md)
- [Code Review Standards](docs/standards/01-CODE-REVIEW-STANDARDS.md)
- [Documentation Standards](docs/standards/00-DOCUMENTATION-STANDARDS.md)

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat(detector): add AWS Secret Access Key detector
fix(engine): fix goroutine leak on worker pool context cancellation
test(entropy): add Shannon entropy edge case tests
```

## License

Your contributions will be licensed under the [MIT License](LICENSE).

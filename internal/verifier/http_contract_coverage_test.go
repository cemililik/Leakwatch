package verifier_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedHTTPVerifierPackages = []string{
	"airtable", "anthropic", "auth0", "bitbucket", "circleci", "cloudflare",
	"databricks", "datadog", "deepseek", "digitalocean", "discord", "dockerhub",
	"doppler", "figma", "github", "gitlab", "grafana", "heroku", "huggingface",
	"infura", "launchdarkly", "linear", "mailgun", "newrelic", "notion", "npm",
	"okta", "openai", "pagerduty", "postmark", "pypi", "rubygems", "sendgrid",
	"sentry", "shopify", "slack", "snyk", "sonarcloud", "stripe", "supabase",
	"teams", "telegram", "terraform", "twilio", "vercel",
}

// TestHTTPVerifierPackages_UseSharedSafetySuite ties network discovery to exact
// package identities and to a directly executed top-level vtest call. A raw
// comment marker, an aliased import, a helper hidden in a non-verifier filename,
// or a dead nested function cannot satisfy the guard.
func TestHTTPVerifierPackages_UseSharedSafetySuite(t *testing.T) {
	entries, err := filepath.Glob("*")
	require.NoError(t, err)
	discovered := make([]string, 0, len(expectedHTTPVerifierPackages))
	for _, entry := range entries {
		info, statErr := filepath.Glob(filepath.Join(entry, "*.go"))
		require.NoError(t, statErr)
		if len(info) == 0 || entry == "internal" || !packageUsesHTTP(t, entry) {
			continue
		}
		discovered = append(discovered, entry)
		assert.True(t, packageRunsVTestDirectly(t, entry),
			"HTTP verifier package %q must execute vtest.Run as the first statement of a top-level Test function", entry)
	}
	sort.Strings(discovered)
	assert.Equal(t, expectedHTTPVerifierPackages, discovered,
		"HTTP verifier package identities changed; add/remove an executable safety contract deliberately")
}

func packageUsesHTTP(t *testing.T, directory string) bool {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.go"))
	require.NoError(t, err)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file := parseGoFile(t, path)
		httpxAliases := importAliases(file, "github.com/HodeTech/leakwatch/internal/verifier/internal/httpx", "httpx")
		httpAliases := importAliases(file, "net/http", "http")
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if httpxAliases[receiver.Name] && selector.Sel.Name == "VerifyToken" {
				found = true
				return false
			}
			if httpAliases[receiver.Name] && (selector.Sel.Name == "NewRequestWithContext" || selector.Sel.Name == "NewRequest") {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func packageRunsVTestDirectly(t *testing.T, directory string) bool {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*_test.go"))
	require.NoError(t, err)
	for _, path := range paths {
		file := parseGoFile(t, path)
		aliases := importAliases(file, "github.com/HodeTech/leakwatch/internal/verifier/internal/vtest", "vtest")
		if len(aliases) == 0 {
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Test") ||
				function.Body == nil || len(function.Body.List) == 0 {
				continue
			}
			expression, ok := function.Body.List[0].(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expression.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Run" {
				continue
			}
			receiver, ok := selector.X.(*ast.Ident)
			if ok && aliases[receiver.Name] {
				return true
			}
		}
	}
	return false
}

func importAliases(file *ast.File, importPath, defaultName string) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		name := defaultName
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "." && name != "_" {
			aliases[name] = true
		}
	}
	return aliases
}

func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	return file
}

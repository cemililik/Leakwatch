package verifier_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPVerifierPackages_UseSharedSafetySuite is the fail-closed registry
// guard for network verifiers. A new package that uses the shared HTTP flow (or
// performs a direct request such as the Teams webhook verifier) cannot enter CI
// without exercising transport failure, cancellation, malformed-body policy
// and transport-error credential redaction through vtest.Run.
func TestHTTPVerifierPackages_UseSharedSafetySuite(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	covered := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "internal" {
			continue
		}
		productionPattern := filepath.Join(entry.Name(), "*_verifier.go")
		usesHTTP := filesCallSelector(t, productionPattern, func(receiver, method string) bool {
			return receiver == "httpx" && method == "VerifyToken" || method == "Do"
		})
		if !usesHTTP {
			continue
		}
		covered++
		testPattern := filepath.Join(entry.Name(), "*_test.go")
		tests := readMatchingFiles(t, testPattern)
		hasSharedSuite := filesCallSelector(t, testPattern, func(receiver, method string) bool {
			return receiver == "vtest" && method == "Run"
		})
		hasReviewedEquivalent := bytes.Contains(tests, []byte("leakwatch:vtest-equivalent"))
		assert.True(t, hasSharedSuite || hasReviewedEquivalent,
			"HTTP verifier package %q must run vtest or declare a reviewed equivalent suite", entry.Name())
	}
	assert.Equal(t, 45, covered,
		"HTTP verifier discovery changed; review the source-pattern guard and every affected contract suite")
}

func filesCallSelector(t *testing.T, pattern string, matches func(receiver, method string) bool) bool {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	require.NoError(t, err)
	for _, path := range paths {
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		require.NoError(t, parseErr)
		found := false
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, _ := selector.X.(*ast.Ident)
			if receiver != nil && matches(receiver.Name, selector.Sel.Name) {
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

func readMatchingFiles(t *testing.T, pattern string) []byte {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	require.NoError(t, err)
	var result []byte
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		result = append(result, contents...)
	}
	return result
}

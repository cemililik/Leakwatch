//go:build unix

package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChunks_SkipsNonRegularFiles pins the explicit file-type guard. Reading a
// named pipe with no writer blocks forever, so a non-regular file must never be
// opened. Today such entries also happen to be filtered by the zero-size branch
// of shouldSkip, so this test does not fail without the type check — it exists
// so the protection is asserted by TYPE and survives any future change to that
// size heuristic (and covers non-regular files that do report a size).
func TestChunks_SkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("AKIAQYRTZ4XN2WV6H8LM\n"), 0o600))
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var paths []string
	for chunk := range New(dir).Chunks(ctx) {
		paths = append(paths, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, paths, "real.txt", "regular files must still be scanned")
	for _, p := range paths {
		assert.NotEqual(t, "pipe", p, "a named pipe must never be read")
	}
}

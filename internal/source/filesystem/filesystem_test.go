package filesystem

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilesystemSource_Type(t *testing.T) {
	s := New("/tmp")
	assert.Equal(t, "filesystem", s.Type())
}

func TestFilesystemSource_New_CleansPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantAbs   bool
		wantClean bool
	}{
		{
			name:      "trailing slash removed",
			input:     "/tmp/foo/",
			wantClean: true,
		},
		{
			name:      "double slash cleaned",
			input:     "/tmp//foo",
			wantClean: true,
		},
		{
			name:      "dot segments resolved",
			input:     "/tmp/foo/../bar",
			wantClean: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.input)
			cleaned := filepath.Clean(tt.input)
			abs, err := filepath.Abs(cleaned)
			if err != nil {
				abs = cleaned
			}
			assert.Equal(t, abs, s.root, "root should be cleaned and absolute")
		})
	}
}

// Validate() calls os.Stat directly against s.root, so these tests genuinely
// need a real filesystem rather than an injectable fs.FS.

func TestFilesystemSource_Validate_ValidDir(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	assert.NoError(t, s.Validate())
}

func TestFilesystemSource_Validate_NonExistentDir(t *testing.T) {
	s := New("/nonexistent/path")
	assert.Error(t, s.Validate())
}

func TestFilesystemSource_Validate_FileNotDir(t *testing.T) {
	f, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	s := New(f.Name())
	err = s.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// shouldSkip is pure filtering logic over a path string and an fs.DirEntry;
// it never touches disk itself, so it can be exercised entirely against
// fs.DirEntry values sourced from an in-memory fstest.MapFS instead of real
// files on disk.

func TestFilesystemSource_ShouldSkip_ExtensionExclusion(t *testing.T) {
	fsys := fstest.MapFS{
		"code.go":   &fstest.MapFile{Data: []byte("package main")},
		"image.png": &fstest.MapFile{Data: []byte("fakepng")},
	}
	entries, err := fsys.ReadDir(".")
	require.NoError(t, err)

	s := New("/scan/root")
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = s.shouldSkip(filepath.Join(s.root, e.Name()), e)
	}

	assert.False(t, got["code.go"], "code.go should not be skipped")
	assert.True(t, got["image.png"], "image.png should be skipped as a binary extension")
}

func TestFilesystemSource_ShouldSkip_MaxFileSize(t *testing.T) {
	bigData := bytes.Repeat([]byte("A"), 1024)
	fsys := fstest.MapFS{
		"small.txt": &fstest.MapFile{Data: []byte("small")},
		"big.txt":   &fstest.MapFile{Data: bigData},
	}
	entries, err := fsys.ReadDir(".")
	require.NoError(t, err)

	s := New("/scan/root", WithMaxFileSize(512))
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = s.shouldSkip(filepath.Join(s.root, e.Name()), e)
	}

	assert.False(t, got["small.txt"], "small.txt is under the size cap")
	assert.True(t, got["big.txt"], "big.txt exceeds the size cap")
}

func TestFilesystemSource_ShouldSkip_EmptyFile(t *testing.T) {
	fsys := fstest.MapFS{
		"empty.txt": &fstest.MapFile{Data: []byte{}},
	}
	entries, err := fsys.ReadDir(".")
	require.NoError(t, err)

	s := New("/scan/root")
	assert.True(t, s.shouldSkip(filepath.Join(s.root, "empty.txt"), entries[0]), "zero-byte files should be skipped")
}

func TestFilesystemSource_ShouldSkip_ExcludePaths(t *testing.T) {
	fsys := fstest.MapFS{
		"main.go": &fstest.MapFile{Data: []byte("package main")},
		"go.sum":  &fstest.MapFile{Data: []byte("checksum")},
	}
	entries, err := fsys.ReadDir(".")
	require.NoError(t, err)

	s := New("/scan/root", WithExcludePaths([]string{"go.sum"}))
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = s.shouldSkip(filepath.Join(s.root, e.Name()), e)
	}

	assert.False(t, got["main.go"], "main.go should not be skipped")
	assert.True(t, got["go.sum"], "go.sum is skipped both by the default lockfile list and the exclude pattern")
}

func TestFilesystemSource_ShouldSkip_SkippedLockfile(t *testing.T) {
	fsys := fstest.MapFS{
		"yarn.lock": &fstest.MapFile{Data: []byte("checksum data")},
	}
	entries, err := fsys.ReadDir(".")
	require.NoError(t, err)

	s := New("/scan/root")
	assert.True(t, s.shouldSkip(filepath.Join(s.root, "yarn.lock"), entries[0]))
}

// Chunks() drives filepath.WalkDir/os.Open against the real filesystem (the
// production code has no injectable fs.FS), so its tests genuinely need
// real files on disk rather than fstest.MapFS.

func TestFilesystemSource_Chunks_ReadsFiles(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("api_key: test123"), 0o644))

	s := New(dir)
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 2)
}

func TestFilesystemSource_Chunks_SkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "text.txt"), []byte("hello world"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binary.dat"), []byte("hello\x00world"), 0o644))

	s := New(dir)
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "text.txt", chunks[0])
}

func TestFilesystemSource_Chunks_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 100; i++ {
		name := filepath.Join(dir, "file"+string(rune('a'+i%26))+".txt")
		_ = os.WriteFile(name, []byte("content"), 0o644)
	}

	s := New(dir, WithBufferSize(1))
	ctx, cancel := context.WithCancel(context.Background())

	ch := s.Chunks(ctx)

	// Get the first chunk, then cancel.
	<-ch
	cancel()

	// Verify the channel eventually closes.
	count := 0
	for range ch {
		count++
	}
	// Buffered chunks may arrive but the channel must close.
	assert.Less(t, count, 100)
}

func TestFilesystemSource_Chunks_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	s := New(dir)
	ctx := context.Background()

	var count int
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestFilesystemSource_Chunks_SkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	dir := t.TempDir()

	// Create a real file.
	realFile := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(realFile, []byte("real content"), 0o644))

	// Create a symlink pointing to the real file.
	symlinkFile := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(realFile, symlinkFile))

	s := New(dir)
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	// Only the real file should be scanned; the symlink should be skipped.
	assert.Len(t, chunks, 1)
	assert.Equal(t, "real.txt", chunks[0])
}

// TestFilesystemSource_Chunks_AppliesShouldSkip is a thin end-to-end check
// that Chunks() actually wires shouldSkip's filtering (extension, exclude
// paths, size) into the real WalkDir traversal; the individual filtering
// rules themselves are covered more thoroughly and cheaply by the
// MapFS-based ShouldSkip unit tests above.
func TestFilesystemSource_Chunks_AppliesShouldSkip(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte("fakepng"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte("checksum"), 0o644))

	bigData := bytes.Repeat([]byte("A"), 1024)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.txt"), bigData, 0o644))

	s := New(dir, WithMaxFileSize(512), WithExcludePaths([]string{"go.sum"}))
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "main.go", chunks[0])
}

func TestFilesystemSource_Chunks_SkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()

	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(filepath.Join(gitDir, "objects"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "objects", "pack-data"), []byte("not a real pack\x00but irrelevant"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\n\trepositoryformatversion = 0"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644))

	s := New(dir)
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "main.go", chunks[0])
}

func TestFilesystemSource_Chunks_ScansGitDirWhenItIsTheExplicitRoot(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config"), []byte("[core]\n\trepositoryformatversion = 0"), 0o644))

	// Pointing the source directly at a .git directory is an explicit,
	// deliberate scan target and must not be silently emptied by the
	// default exclusion, which only skips .git when encountered while
	// walking a larger tree.
	s := New(gitDir)
	ctx := context.Background()

	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "config", chunks[0])
}

// readIfNotBinary opens files directly via os.Open, so its tests genuinely
// need real files on disk.

func TestReadIfNotBinary_ReturnsContentForTextFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "text.txt")
	want := []byte("hello world")
	require.NoError(t, os.WriteFile(path, want, 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestReadIfNotBinary_ReturnsNilForBinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.dat")
	require.NoError(t, os.WriteFile(path, []byte("hello\x00world"), 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestReadIfNotBinary_DetectsBinaryFromLeadingByte(t *testing.T) {
	// The null byte is the very first byte, so a bounded prefix read is
	// sufficient to detect it without reading the rest of a large file.
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.dat")
	data := append([]byte{0x00}, bytes.Repeat([]byte("A"), 1<<20)...)
	require.NoError(t, os.WriteFile(path, data, 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestReadIfNotBinary_ReadsFileLargerThanPeekWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	want := bytes.Repeat([]byte("A"), binaryPeekSize*3+17)
	require.NoError(t, os.WriteFile(path, want, 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestReadIfNotBinary_FileSmallerThanPeekWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.txt")
	want := []byte("tiny")
	require.NoError(t, os.WriteFile(path, want, 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestReadIfNotBinary_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	got, err := readIfNotBinary(path)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestReadIfNotBinary_NonExistentFile(t *testing.T) {
	_, err := readIfNotBinary("/nonexistent/path/file.txt")
	assert.Error(t, err)
}

package container

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/source"
)

func TestContainerSource_Type_ReturnsContainer(t *testing.T) {
	s := New("nginx:latest")
	assert.Equal(t, "container", s.Type())
}

func TestContainerSource_Validate_ValidRef_ReturnsNoError(t *testing.T) {
	s := New("nginx:latest")
	assert.NoError(t, s.Validate(context.Background()))
}

func TestContainerSource_Validate_InvalidRef_ReturnsError(t *testing.T) {
	s := New(":::invalid")
	assert.Error(t, s.Validate(context.Background()))
}

func TestContainerSource_Validate_FullRef_ReturnsNoError(t *testing.T) {
	s := New("ghcr.io/org/repo:v1.0.0")
	assert.NoError(t, s.Validate(context.Background()))
}

func TestShouldSkipContainerPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "doc path is skipped",
			path: "/usr/share/doc/something",
			want: true,
		},
		{
			name: "man path is skipped",
			path: "/usr/share/man/man1/ls.1",
			want: true,
		},
		{
			name: "app file is not skipped",
			path: "/app/config.yaml",
			want: false,
		},
		{
			name: "etc file is not skipped",
			path: "/etc/environment",
			want: false,
		},
		{
			name: "root file is not skipped",
			path: "app.conf",
			want: false,
		},
		{
			name: "locale path is skipped",
			path: "/usr/share/locale/en/messages.mo",
			want: true,
		},
		{
			name: "usr lib path is skipped",
			path: "/usr/lib/libfoo.so",
			want: true,
		},
		{
			name: "var cache path is skipped",
			path: "/var/cache/apt/pkgcache.bin",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldSkipContainerPath(tt.path))
		})
	}
}

// buildTarArchive creates an in-memory tar archive from the given entries.
func buildTarArchive(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Size:     int64(len(e.data)),
			Typeflag: e.typeflag,
			Mode:     0o644,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if len(e.data) > 0 {
			_, err := tw.Write(e.data)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return &buf
}

type tarEntry struct {
	name     string
	data     []byte
	typeflag byte
}

func collectChunks(ch <-chan source.Chunk) []source.Chunk {
	var chunks []source.Chunk
	for c := range ch {
		chunks = append(chunks, c)
	}
	return chunks
}

func TestScanTarLayer_RegularFile_ProducesChunk(t *testing.T) {
	content := []byte("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/config.env", data: content, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	require.Len(t, chunks, 1)
	assert.Equal(t, content, chunks[0].Data)
	assert.Equal(t, "container", chunks[0].SourceMetadata.SourceType)
	assert.Equal(t, "test:latest", chunks[0].SourceMetadata.Image)
	assert.Equal(t, "sha256:abc123", chunks[0].SourceMetadata.Layer)
	assert.Equal(t, 0, chunks[0].SourceMetadata.LayerIdx)
	assert.Equal(t, "app/config.env", chunks[0].SourceMetadata.FilePath)
}

func TestScanTarLayer_DirectoryEntry_Skipped(t *testing.T) {
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/", data: nil, typeflag: tar.TypeDir},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestScanTarLayer_BinaryFile_Skipped(t *testing.T) {
	// Binary data with null bytes within the first 8KB.
	binaryData := make([]byte, 100)
	binaryData[0] = 0x00
	binaryData[1] = 0x7f
	binaryData[2] = 0x45
	binaryData[3] = 0x4c
	binaryData[4] = 0x46

	buf := buildTarArchive(t, []tarEntry{
		{name: "app/binary.dat", data: binaryData, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestScanTarLayer_LargeFile_Skipped(t *testing.T) {
	// Create a source with a very small max file size.
	s := New("test:latest", WithMaxFileSize(10))

	content := []byte("this content is longer than 10 bytes")
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/large.txt", data: content, typeflag: tar.TypeReg},
	})

	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestScanTarLayer_PathTraversal_Skipped(t *testing.T) {
	content := []byte("secret=value")
	buf := buildTarArchive(t, []tarEntry{
		{name: "../../etc/passwd", data: content, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestScanTarLayer_ContextCancellation_Stops(t *testing.T) {
	// Create archive with multiple files.
	entries := make([]tarEntry, 100)
	for i := range entries {
		entries[i] = tarEntry{
			name:     "app/file" + string(rune('a'+i%26)) + ".txt",
			data:     []byte("content"),
			typeflag: tar.TypeReg,
		}
	}
	buf := buildTarArchive(t, entries)

	s := New("test:latest")
	ch := make(chan source.Chunk, 1) // small buffer to force blocking

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context immediately.
	cancel()

	tr := tar.NewReader(buf)
	s.scanTarLayer(ctx, ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	// With cancelled context, should produce zero or very few chunks.
	assert.Less(t, len(chunks), 100)
}

func TestScanTarLayer_EmptyFile_Skipped(t *testing.T) {
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/empty.txt", data: []byte{}, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestScanTarLayer_SkippedContainerPath_Skipped(t *testing.T) {
	content := []byte("some doc content")
	buf := buildTarArchive(t, []tarEntry{
		{name: "usr/share/doc/readme.txt", data: content, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestWithMaxFileSize_InvalidValue_NoOp(t *testing.T) {
	s := New("test:latest")
	original := s.maxFileSize

	WithMaxFileSize(0)(s)
	assert.Equal(t, original, s.maxFileSize)

	WithMaxFileSize(-1)(s)
	assert.Equal(t, original, s.maxFileSize)
}

func TestWithBufferSize_InvalidValue_NoOp(t *testing.T) {
	s := New("test:latest")
	original := s.bufferSize

	WithBufferSize(0)(s)
	assert.Equal(t, original, s.bufferSize)

	WithBufferSize(-1)(s)
	assert.Equal(t, original, s.bufferSize)
}

func TestWithMaxFileSize_ValidValue_Applied(t *testing.T) {
	s := New("test:latest", WithMaxFileSize(1024))
	assert.Equal(t, int64(1024), s.maxFileSize)
}

func TestWithBufferSize_ValidValue_Applied(t *testing.T) {
	s := New("test:latest", WithBufferSize(128))
	assert.Equal(t, 128, s.bufferSize)
}

func TestScanTarLayer_MultipleFiles_ProducesMultipleChunks(t *testing.T) {
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/a.txt", data: []byte("file-a"), typeflag: tar.TypeReg},
		{name: "app/b.txt", data: []byte("file-b"), typeflag: tar.TypeReg},
		{name: "app/c.txt", data: []byte("file-c"), typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 2, "sha256:def456")
	close(ch)

	chunks := collectChunks(ch)
	require.Len(t, chunks, 3)

	// Verify layer metadata is consistent.
	for _, c := range chunks {
		assert.Equal(t, 2, c.SourceMetadata.LayerIdx)
		assert.Equal(t, "sha256:def456", c.SourceMetadata.Layer)
	}
}

func TestScanTarLayer_WithExcludePaths_Skipped(t *testing.T) {
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/keep.txt", data: []byte("keep me"), typeflag: tar.TypeReg},
		{name: "vendor/skip.txt", data: []byte("skip me"), typeflag: tar.TypeReg},
	})

	s := New("test:latest", WithExcludePaths([]string{"vendor/**"}))
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	require.Len(t, chunks, 1)
	assert.Equal(t, "app/keep.txt", chunks[0].SourceMetadata.FilePath)
}

func TestContainerSource_New_WithExcludePaths_StoresPatterns(t *testing.T) {
	s := New("test:latest", WithExcludePaths([]string{"a/**", "b"}))
	assert.Equal(t, []string{"a/**", "b"}, s.excludePaths)
}

func TestScanTarLayer_AbsolutePath_Skipped(t *testing.T) {
	content := []byte("secret=value")
	buf := buildTarArchive(t, []tarEntry{
		{name: "/etc/passwd", data: content, typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

func TestSanitizeTarPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPath string
		wantOK   bool
	}{
		{name: "simple relative path", input: "app/config.env", wantPath: "app/config.env", wantOK: true},
		{name: "dot-cleaned path", input: "app/./config.env", wantPath: "app/config.env", wantOK: true},
		{name: "interior dotdot stays in tree", input: "app/sub/../config.env", wantPath: "app/config.env", wantOK: true},
		{name: "leading dotdot rejected", input: "../etc/passwd", wantOK: false},
		{name: "nested leading dotdot rejected", input: "../../etc/passwd", wantOK: false},
		{name: "absolute unix path rejected", input: "/etc/passwd", wantOK: false},
		{name: "escapes root via dotdot rejected", input: "a/../../etc/passwd", wantOK: false},
		{name: "bare dotdot rejected", input: "..", wantOK: false},
		{name: "backslash traversal rejected", input: `..\..\etc\passwd`, wantOK: false},
		{name: "single backslash traversal rejected", input: `..\etc\passwd`, wantOK: false},
		{name: "backslash separators normalized", input: `app\sub\config.env`, wantPath: "app/sub/config.env", wantOK: true},
		{name: "windows drive-letter path rejected", input: `C:\Windows\system32`, wantOK: false},
		{name: "windows drive-letter slash path rejected", input: "C:/Windows/system32", wantOK: false},
		{name: "unc path rejected", input: `\\host\share\file`, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeTarPath(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantPath, got)
			}
		})
	}
}

func TestScanTarLayer_BinaryExtension_Skipped(t *testing.T) {
	buf := buildTarArchive(t, []tarEntry{
		{name: "app/image.png", data: []byte("not really png"), typeflag: tar.TypeReg},
	})

	s := New("test:latest")
	ch := make(chan source.Chunk, 10)

	tr := tar.NewReader(buf)
	s.scanTarLayer(context.Background(), ch, tr, 0, "sha256:abc123")
	close(ch)

	chunks := collectChunks(ch)
	assert.Empty(t, chunks)
}

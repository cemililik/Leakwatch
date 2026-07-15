package container

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/source"
)

// buildLayer creates an in-memory v1.Layer from the given tar entries.
func buildLayer(t *testing.T, entries []tarEntry) v1.Layer {
	t.Helper()
	raw := buildTarArchive(t, entries).Bytes()
	// LayerFromOpener (not the deprecated LayerFromReader) may open the source
	// more than once, so hand it a fresh reader over the captured bytes.
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	require.NoError(t, err)
	return layer
}

// buildImage assembles an in-memory v1.Image from the given config and layers.
func buildImage(t *testing.T, cfg v1.Config, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.Config(empty.Image, cfg)
	require.NoError(t, err)
	img, err = mutate.AppendLayers(img, layers...)
	require.NoError(t, err)
	return img
}

// withImage injects a fixed in-memory image into the source's loader so
// Chunks() runs its full orchestration path with no network access.
func withImage(img v1.Image) Option {
	return func(s *ContainerSource) {
		s.loadImage = func(_ context.Context, _ name.Reference) (v1.Image, error) {
			return img, nil
		}
	}
}

func TestChunks_MultiLayerImage_EmitsChunksWithMetadata(t *testing.T) {
	layer0 := buildLayer(t, []tarEntry{
		{name: "app/config.env", data: []byte("AWS_SECRET_ACCESS_KEY=synthetic"), typeflag: tar.TypeReg},
	})
	layer1 := buildLayer(t, []tarEntry{
		{name: "srv/secrets.txt", data: []byte("token=synthetic-token"), typeflag: tar.TypeReg},
	})
	img := buildImage(t, v1.Config{}, layer0, layer1)

	s := New("test:latest", withImage(img))
	chunks := collectChunks(s.Chunks(context.Background()))

	// Two layer files (config blob is empty here).
	require.Len(t, chunks, 2)

	byPath := map[string]source.Chunk{}
	for _, c := range chunks {
		byPath[c.SourceMetadata.FilePath] = c
	}

	c0, ok := byPath["app/config.env"]
	require.True(t, ok)
	assert.Equal(t, "container", c0.SourceMetadata.SourceType)
	assert.Equal(t, "test:latest", c0.SourceMetadata.Image)
	assert.Equal(t, 0, c0.SourceMetadata.LayerIdx)
	assert.NotEmpty(t, c0.SourceMetadata.Layer)

	c1, ok := byPath["srv/secrets.txt"]
	require.True(t, ok)
	assert.Equal(t, 1, c1.SourceMetadata.LayerIdx)
	assert.NotEqual(t, c0.SourceMetadata.Layer, c1.SourceMetadata.Layer)
}

func TestChunks_ConfigBlob_ScannedForSecrets(t *testing.T) {
	cfg := v1.Config{
		Env:        []string{"AWS_SECRET_ACCESS_KEY=synthetic-env-secret", "PATH=/usr/bin"},
		Labels:     map[string]string{"maintainer": "test", "api.key": "synthetic-label-secret"},
		Entrypoint: []string{"/entrypoint.sh"},
		Cmd:        []string{"--token", "synthetic-cmd-secret"},
	}
	img := buildImage(t, cfg)

	s := New("test:latest", withImage(img))
	chunks := collectChunks(s.Chunks(context.Background()))

	require.Len(t, chunks, 1)
	cfgChunk := chunks[0]
	assert.Equal(t, "<image config>", cfgChunk.SourceMetadata.FilePath)
	assert.Equal(t, "config", cfgChunk.SourceMetadata.Layer)
	assert.Equal(t, -1, cfgChunk.SourceMetadata.LayerIdx)

	data := string(cfgChunk.Data)
	assert.Contains(t, data, "ENV AWS_SECRET_ACCESS_KEY=synthetic-env-secret")
	assert.Contains(t, data, "LABEL api.key=synthetic-label-secret")
	assert.Contains(t, data, "ENTRYPOINT /entrypoint.sh")
	assert.Contains(t, data, "CMD --token synthetic-cmd-secret")
}

func TestChunks_EmptyConfig_NoConfigChunk(t *testing.T) {
	layer := buildLayer(t, []tarEntry{
		{name: "app/a.txt", data: []byte("value"), typeflag: tar.TypeReg},
	})
	img := buildImage(t, v1.Config{}, layer)

	s := New("test:latest", withImage(img))
	chunks := collectChunks(s.Chunks(context.Background()))

	require.Len(t, chunks, 1)
	assert.Equal(t, "app/a.txt", chunks[0].SourceMetadata.FilePath)
}

func TestChunks_LoadImageError_ClosesChannelCleanly(t *testing.T) {
	s := New("test:latest")
	s.loadImage = func(_ context.Context, _ name.Reference) (v1.Image, error) {
		return nil, errors.New("pull failed")
	}

	chunks := collectChunks(s.Chunks(context.Background()))
	assert.Empty(t, chunks)
}

func TestChunks_InvalidReference_ClosesChannelCleanly(t *testing.T) {
	// Loader must never be reached when the reference itself is unparseable.
	s := New(":::invalid", withImage(buildImage(t, v1.Config{})))
	chunks := collectChunks(s.Chunks(context.Background()))
	assert.Empty(t, chunks)
}

func TestChunks_CancelledContext_StopsBeforeEmitting(t *testing.T) {
	layer := buildLayer(t, []tarEntry{
		{name: "app/a.txt", data: []byte("value"), typeflag: tar.TypeReg},
	})
	img := buildImage(t, v1.Config{}, layer)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New("test:latest", withImage(img))
	chunks := collectChunks(s.Chunks(ctx))
	assert.Empty(t, chunks)
}

func TestChunks_ImageSizeCeiling_AbortsRemainingLayers(t *testing.T) {
	layer0 := buildLayer(t, []tarEntry{
		{name: "app/a.txt", data: []byte("value-a"), typeflag: tar.TypeReg},
	})
	layer1 := buildLayer(t, []tarEntry{
		{name: "app/b.txt", data: []byte("value-b"), typeflag: tar.TypeReg},
	})
	img := buildImage(t, v1.Config{}, layer0, layer1)

	// A 1-byte image ceiling trips inside the first layer's decompression and
	// skips every remaining layer, so no layer file chunks are emitted.
	s := New("test:latest", withImage(img), WithMaxImageSize(1))
	chunks := collectChunks(s.Chunks(context.Background()))
	assert.Empty(t, chunks)
}

func TestChunks_LayerSizeCeiling_AbortsLayer(t *testing.T) {
	layer := buildLayer(t, []tarEntry{
		{name: "app/a.txt", data: []byte("value"), typeflag: tar.TypeReg},
	})
	img := buildImage(t, v1.Config{}, layer)

	// A 1-byte per-layer ceiling trips on the first read of the tar header.
	s := New("test:latest", withImage(img), WithMaxLayerSize(1))
	chunks := collectChunks(s.Chunks(context.Background()))
	assert.Empty(t, chunks)
}

func TestLimitedCountingReader_WithinLimits_ReadsAll(t *testing.T) {
	src := strings.NewReader("hello world")
	var total int64
	lr := &limitedCountingReader{r: src, layerRemaining: 100, imageTotal: &total, imageMax: 100}

	got, err := io.ReadAll(lr)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(got))
	assert.Equal(t, int64(len("hello world")), total)
}

func TestLimitedCountingReader_ExceedsLayerLimit_ReturnsError(t *testing.T) {
	src := strings.NewReader("this is longer than the layer budget")
	var total int64
	lr := &limitedCountingReader{r: src, layerRemaining: 5, imageTotal: &total, imageMax: 1 << 30}

	_, err := io.ReadAll(lr)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errDecompressionLimit))
	assert.LessOrEqual(t, total, int64(5))
}

func TestLimitedCountingReader_ExceedsImageLimit_ReturnsError(t *testing.T) {
	src := strings.NewReader("this is longer than the image budget")
	var total int64 = 3 // pretend prior layers already consumed 3 bytes
	lr := &limitedCountingReader{r: src, layerRemaining: 1 << 30, imageTotal: &total, imageMax: 5}

	_, err := io.ReadAll(lr)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errDecompressionLimit))
}

func TestWithMaxLayerSize_InvalidValue_NoOp(t *testing.T) {
	s := New("test:latest")
	original := s.maxLayerSize
	WithMaxLayerSize(0)(s)
	assert.Equal(t, original, s.maxLayerSize)
	WithMaxLayerSize(-1)(s)
	assert.Equal(t, original, s.maxLayerSize)
}

func TestWithMaxImageSize_InvalidValue_NoOp(t *testing.T) {
	s := New("test:latest")
	original := s.maxImageSize
	WithMaxImageSize(0)(s)
	assert.Equal(t, original, s.maxImageSize)
	WithMaxImageSize(-1)(s)
	assert.Equal(t, original, s.maxImageSize)
}

func TestWithMaxLayerSize_ValidValue_Applied(t *testing.T) {
	s := New("test:latest", WithMaxLayerSize(4096))
	assert.Equal(t, int64(4096), s.maxLayerSize)
}

func TestWithMaxImageSize_ValidValue_Applied(t *testing.T) {
	s := New("test:latest", WithMaxImageSize(8192))
	assert.Equal(t, int64(8192), s.maxImageSize)
}

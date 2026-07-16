// Package container provides a container image scan source.
// It pulls and inspects OCI/Docker images layer by layer without
// requiring a running Docker daemon (daemon-less, via go-containerregistry).
package container

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const defaultMaxFileSize int64 = 10 * 1024 * 1024

// Decompression-bomb defenses: cap the cumulative number of *decompressed*
// bytes read from a single layer and from the whole image. A malicious image
// can declare an extreme compression ratio (a "zip bomb") or a huge number of
// just-under-limit files; the per-file cap alone does not bound the total
// decompression work. These ceilings are deliberately generous so they never
// trip on real-world images (multi-GB images are legitimate) while still
// guaranteeing the scan cannot be forced to decompress unbounded data.
const (
	// defaultMaxLayerSize caps decompressed bytes read from one layer (2 GiB).
	defaultMaxLayerSize int64 = 2 * 1024 * 1024 * 1024
	// defaultMaxImageSize caps decompressed bytes read across all layers (10 GiB).
	defaultMaxImageSize int64 = 10 * 1024 * 1024 * 1024
)

// errDecompressionLimit is returned by the counting reader once a per-layer or
// per-image decompressed-byte ceiling is exceeded, signalling the scan to abort
// the offending layer rather than continue decompressing attacker-controlled data.
var errDecompressionLimit = errors.New("decompression limit exceeded")

// ContainerSource scans container image layers for secrets.
type ContainerSource struct {
	imageRef     string
	maxFileSize  int64
	maxLayerSize int64
	maxImageSize int64
	bufferSize   int
	excludePaths []string

	// loadImage resolves an image reference to a v1.Image. It defaults to a
	// daemon-less remote pull and is overridable in tests to drive the
	// orchestration path against an in-memory image without any network.
	loadImage func(ctx context.Context, ref name.Reference) (v1.Image, error)

	// err records the first terminal failure that aborted image scanning (a
	// reference parse error, a pull failure, a layer-list failure, or a
	// decompression-limit trip). It is written only by the Chunks goroutine,
	// before it closes the chunks channel, and read only via Err after that
	// channel has been drained; the channel close/drain is the happens-before
	// edge, so no extra synchronization is needed.
	err error
}

// New creates a new ContainerSource for the given image reference.
func New(imageRef string, opts ...Option) *ContainerSource {
	s := &ContainerSource{
		imageRef:     imageRef,
		maxFileSize:  defaultMaxFileSize,
		maxLayerSize: defaultMaxLayerSize,
		maxImageSize: defaultMaxImageSize,
		bufferSize:   64,
		loadImage:    remotePull,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// remotePull pulls an image daemon-less from a remote registry.
func remotePull(ctx context.Context, ref name.Reference) (v1.Image, error) {
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("pull image %q: %w", ref.String(), err)
	}
	return img, nil
}

// Type returns the source type identifier.
func (s *ContainerSource) Type() string {
	return "container"
}

// Err returns the first terminal error that aborted image scanning, or nil if it
// completed normally. It must only be called after the channel returned by Chunks
// has been fully drained (closed).
func (s *ContainerSource) Err() error {
	return s.err
}

// captureErr records the first terminal error that aborted chunk production. It
// is called only from the single Chunks goroutine (directly or via scanImage /
// scanTarLayer), before close(ch), so a plain field write is safe: the channel
// close/drain publishes it to Err's reader. Context cancellation is never
// recorded because it is reported through the context, not Err.
func (s *ContainerSource) captureErr(err error) {
	if err == nil || s.err != nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	s.err = err
}

// Validate checks that the image reference is parseable and accessible.
func (s *ContainerSource) Validate() error {
	_, err := name.ParseReference(s.imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference %q: %w", s.imageRef, err)
	}
	return nil
}

// Chunks pulls the image and sends file contents from each layer as chunks.
func (s *ContainerSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		ref, err := name.ParseReference(s.imageRef)
		if err != nil {
			slog.Error("failed to parse image reference", "image", s.imageRef, "error", err)
			s.captureErr(fmt.Errorf("invalid image reference %q: %w", s.imageRef, err))
			return
		}

		img, err := s.loadImage(ctx, ref)
		if err != nil {
			slog.Error("failed to pull image", "image", s.imageRef, "error", err)
			s.captureErr(fmt.Errorf("failed to pull image %q: %w", s.imageRef, err))
			return
		}

		s.scanImage(ctx, ch, img)
	}()
	return ch
}

// scanImage scans an image's config blob and every layer's filesystem contents,
// enforcing the cumulative decompression ceilings across the whole image.
func (s *ContainerSource) scanImage(ctx context.Context, ch chan<- source.Chunk, img v1.Image) {
	// Scan the image config blob (ENV/LABEL/CMD/ENTRYPOINT) — a well-known
	// leakage vector (e.g. ENV AWS_SECRET_ACCESS_KEY=...) that never appears
	// in any layer's filesystem.
	s.scanConfig(ctx, ch, img)

	layers, err := img.Layers()
	if err != nil {
		slog.Error("failed to get image layers", "image", s.imageRef, "error", err)
		s.captureErr(fmt.Errorf("failed to read image layers for %q: %w", s.imageRef, err))
		return
	}

	slog.Info("scanning container image", "image", s.imageRef, "layers", len(layers))

	// imageDecompressed accumulates decompressed bytes across all layers so a
	// single image cannot force unbounded total decompression work.
	var imageDecompressed int64

	for idx, layer := range layers {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if imageDecompressed > s.maxImageSize {
			slog.Warn("image decompression ceiling exceeded, aborting remaining layers",
				"image", s.imageRef, "limit_bytes", s.maxImageSize)
			// The scan is truncated by the anti-decompression-bomb ceiling, so it
			// did not cover the whole image; record it as terminal so an empty or
			// partial result is not mistaken for a clean scan.
			s.captureErr(fmt.Errorf("container image scan truncated: %w", errDecompressionLimit))
			return
		}

		digest, err := layer.Digest()
		if err != nil {
			// Without a digest we cannot produce a meaningful layer ID
			// (digest.String() would yield ":"), so skip the layer.
			slog.Warn("failed to get layer digest, skipping layer", "layer", idx, "error", err)
			continue
		}
		layerID := digest.String()

		reader, err := layer.Uncompressed()
		if err != nil {
			slog.Warn("failed to read layer", "layer", idx, "error", err)
			continue
		}

		func() {
			defer func() { _ = reader.Close() }()
			// Wrap the decompressed stream so both the per-layer and the
			// cumulative per-image byte ceilings are enforced as the tar
			// reader pulls data through it.
			counting := &limitedCountingReader{
				r:              reader,
				layerRemaining: s.maxLayerSize,
				imageTotal:     &imageDecompressed,
				imageMax:       s.maxImageSize,
			}
			s.scanTarLayer(ctx, ch, tar.NewReader(counting), idx, layerID)
		}()
	}

	slog.Info("container image scan completed", "image", s.imageRef)
}

// scanConfig scans the image config blob for secrets baked into ENV, LABEL,
// CMD, or ENTRYPOINT directives, emitting them as a single synthetic chunk.
func (s *ContainerSource) scanConfig(ctx context.Context, ch chan<- source.Chunk, img v1.Image) {
	cfgFile, err := img.ConfigFile()
	if err != nil {
		slog.Warn("failed to read image config", "image", s.imageRef, "error", err)
		return
	}

	data := renderConfigBlob(cfgFile.Config)
	if len(data) == 0 {
		return
	}

	select {
	case ch <- source.Chunk{
		Data: data,
		SourceMetadata: finding.SourceMetadata{
			SourceType: "container",
			Image:      s.imageRef,
			Layer:      "config",
			LayerIdx:   -1,
			FilePath:   "<image config>",
		},
	}:
	case <-ctx.Done():
	}
}

// renderConfigBlob renders the scannable directives of an image config into a
// deterministic, newline-separated text blob. Returns nil when nothing is set.
func renderConfigBlob(cfg v1.Config) []byte {
	var lines []string
	for _, e := range cfg.Env {
		lines = append(lines, "ENV "+e)
	}
	keys := make([]string, 0, len(cfg.Labels))
	for k := range cfg.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, "LABEL "+k+"="+cfg.Labels[k])
	}
	if len(cfg.Entrypoint) > 0 {
		lines = append(lines, "ENTRYPOINT "+strings.Join(cfg.Entrypoint, " "))
	}
	if len(cfg.Cmd) > 0 {
		lines = append(lines, "CMD "+strings.Join(cfg.Cmd, " "))
	}
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func (s *ContainerSource) scanTarLayer(ctx context.Context, ch chan<- source.Chunk, tr *tar.Reader, layerIdx int, layerID string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if errors.Is(err, errDecompressionLimit) {
			slog.Warn("layer decompression ceiling exceeded, aborting layer",
				"layer", layerIdx, "limit_bytes", s.maxLayerSize)
			s.captureErr(fmt.Errorf("container layer %d scan truncated: %w", layerIdx, errDecompressionLimit))
			break
		}
		if err != nil {
			slog.Warn("failed to read tar entry", "layer", layerIdx, "error", err)
			break
		}

		// Skip directories and non-regular files.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Skip files that are empty or exceed the size limit.
		if header.Size > s.maxFileSize || header.Size == 0 {
			continue
		}

		// Skip auto-generated lock files.
		if filter.IsSkippedFilename(header.Name) {
			continue
		}

		// Skip binary extensions.
		if filter.IsExcludedExtension(header.Name, nil) {
			continue
		}

		// Skip common non-secret paths.
		if shouldSkipContainerPath(header.Name) {
			continue
		}

		cleanPath, ok := sanitizeTarPath(header.Name)
		if !ok {
			slog.Warn("skipping tar entry with unsafe path", "path", header.Name)
			continue
		}

		// Skip files matching exclude-path globs (relative cleaned path).
		if filter.MatchesGlob(cleanPath, s.excludePaths) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, s.maxFileSize))
		if err != nil {
			if errors.Is(err, errDecompressionLimit) {
				slog.Warn("layer decompression ceiling exceeded, aborting layer",
					"layer", layerIdx, "limit_bytes", s.maxLayerSize)
				s.captureErr(fmt.Errorf("container layer %d scan truncated: %w", layerIdx, errDecompressionLimit))
				break
			}
			slog.Warn("failed to read file from layer", "file", header.Name, "layer", layerIdx, "error", err)
			continue
		}

		if filter.IsBinaryFile(data) {
			continue
		}

		select {
		case ch <- source.Chunk{
			Data: data,
			SourceMetadata: finding.SourceMetadata{
				SourceType: "container",
				Image:      s.imageRef,
				Layer:      layerID,
				LayerIdx:   layerIdx,
				FilePath:   cleanPath,
			},
		}:
		case <-ctx.Done():
			return
		}
	}
}

// limitedCountingReader enforces a per-layer decompressed-byte ceiling while
// accumulating every byte read into a shared per-image total. Once either the
// per-layer remaining budget is exhausted or the per-image total exceeds its
// maximum, Read returns errDecompressionLimit so the tar reader aborts instead
// of decompressing further attacker-controlled data.
type limitedCountingReader struct {
	r              io.Reader
	layerRemaining int64
	imageTotal     *int64
	imageMax       int64
}

func (lr *limitedCountingReader) Read(p []byte) (int, error) {
	if lr.layerRemaining <= 0 {
		return 0, errDecompressionLimit
	}
	if int64(len(p)) > lr.layerRemaining {
		p = p[:lr.layerRemaining]
	}
	n, err := lr.r.Read(p)
	lr.layerRemaining -= int64(n)
	*lr.imageTotal += int64(n)
	if *lr.imageTotal > lr.imageMax {
		return n, errDecompressionLimit
	}
	return n, err
}

// sanitizeTarPath validates a tar entry name and returns a cleaned, slash-based
// relative path safe for use as a finding location. It rejects absolute paths
// (Unix, Windows drive-letter, and UNC), Windows drive-relative paths, and any
// path that escapes the archive root via a leading ".." segment.
// The boolean result is false when the entry must be skipped.
func sanitizeTarPath(name string) (string, bool) {
	// Normalize separators to forward slashes independent of the host OS.
	// filepath.ToSlash only rewrites the *host* separator (a no-op for
	// backslashes on Linux/macOS), so replace backslashes explicitly to make
	// backslash-based traversal (e.g. `..\..\etc\passwd`) detectable on every
	// platform this tool ships for.
	slashed := strings.ReplaceAll(name, "\\", "/")

	// Reject absolute paths: Unix ("/etc/..."), the host's own notion of
	// absolute, UNC ("//host/share"), and Windows drive-letter ("C:/...").
	if path.IsAbs(slashed) || filepath.IsAbs(name) ||
		strings.HasPrefix(slashed, "//") || hasWindowsVolume(slashed) {
		return "", false
	}

	clean := path.Clean(slashed)

	// Reject traversal: a clean path of ".." or one beginning with "../"
	// escapes the archive root.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}

	return clean, true
}

// hasWindowsVolume reports whether a slash-normalized path begins with a
// Windows volume specifier such as "C:" or "C:/foo".
func hasWindowsVolume(slashed string) bool {
	if len(slashed) < 2 || slashed[1] != ':' {
		return false
	}
	c := slashed[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// shouldSkipContainerPath returns true for paths unlikely to contain secrets.
func shouldSkipContainerPath(path string) bool {
	skipPrefixes := []string{
		"usr/share/doc/",
		"usr/share/man/",
		"usr/share/locale/",
		"usr/lib/",
		"var/cache/",
	}
	clean := strings.TrimPrefix(filepath.ToSlash(path), "/")
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

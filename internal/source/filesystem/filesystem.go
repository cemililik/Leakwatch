// Package filesystem provides a filesystem-based scan source.
package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// defaultMaxFileSize is the maximum file size to scan (10 MB).
const defaultMaxFileSize int64 = 10 * 1024 * 1024

// binaryPeekSize is the number of leading bytes read to sniff whether a file
// is binary before the rest of the file is read into memory. It mirrors the
// window that filter.IsBinaryFile inspects.
const binaryPeekSize = 8192

// vcsDirName is the version-control metadata directory excluded by default
// from every filesystem scan (unless it is the explicit scan root).
const vcsDirName = ".git"

// FilesystemSource is a filesystem-based scan source. It scans one or more
// roots, each of which may be a directory (walked recursively) or a single
// file (scanned on its own).
type FilesystemSource struct {
	roots        []string
	maxFileSize  int64
	excludeExts  []string
	excludePaths []string
	bufferSize   int

	// err records the first terminal failure that aborted the walk. It is
	// written only by the Chunks goroutine, before it closes the chunks channel,
	// and read only via Err after that channel has been drained; the channel
	// close/drain is the happens-before edge, so no extra synchronization is
	// needed.
	err error
}

// New creates a new FilesystemSource for a single root. The root path is
// cleaned and resolved to an absolute path. The root may be a directory or a
// single file.
func New(root string, opts ...Option) *FilesystemSource {
	return NewMulti([]string{root}, opts...)
}

// NewMulti creates a FilesystemSource that scans several roots in one pass.
// Each root is cleaned and resolved to an absolute path and may be a directory
// (walked recursively) or a single file. A file reachable from more than one
// root is scanned only once.
func NewMulti(roots []string, opts ...Option) *FilesystemSource {
	absRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		absRoot, err := filepath.Abs(cleanRoot)
		if err != nil {
			absRoot = cleanRoot
		}
		absRoots = append(absRoots, absRoot)
	}

	s := &FilesystemSource{
		roots:       absRoots,
		maxFileSize: defaultMaxFileSize,
		bufferSize:  64,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type.
func (s *FilesystemSource) Type() string {
	return "filesystem"
}

// Validate checks that every scan root exists and is accessible. A root may be
// either a directory or a regular file; only inaccessibility (e.g. a
// non-existent path or a permission error) is rejected.
func (s *FilesystemSource) Validate() error {
	if len(s.roots) == 0 {
		return fmt.Errorf("no scan paths provided")
	}
	for _, root := range s.roots {
		if _, err := os.Stat(root); err != nil {
			return fmt.Errorf("source path inaccessible %s: %w", root, err)
		}
	}
	return nil
}

// Chunks walks every configured root and sends chunks over a channel.
func (s *FilesystemSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)
		// visited dedups files reachable from more than one root (e.g. a
		// directory root and a file inside it both passed as arguments) so a
		// secret is never reported twice for the same file.
		visited := make(map[string]struct{})
		for _, root := range s.roots {
			if err := s.walkRoot(ctx, root, ch, visited); err != nil {
				if ctx.Err() == nil {
					slog.Error("filesystem scan failed", "error", err)
					// Record the terminal walk/setup failure before the deferred
					// close(ch) runs so the engine can distinguish a failed scan
					// from a genuinely empty one. Context cancellation is
					// intentionally not captured (it is reported through the
					// context, not Err).
					s.err = fmt.Errorf("filesystem scan failed: %w", err)
				}
				return
			}
		}
	}()
	return ch
}

// walkRoot walks a single root, emitting a chunk for each non-skipped,
// non-binary file. When the root is a single file, relBase is its parent
// directory so the emitted FilePath is the file's name (mirroring the
// directory case, where paths are reported relative to the root). It returns a
// non-nil error only for a terminal failure (a failed root entry or context
// cancellation); per-entry errors deeper in the tree are logged and skipped.
func (s *FilesystemSource) walkRoot(ctx context.Context, root string, ch chan<- source.Chunk, visited map[string]struct{}) error {
	relBase := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		relBase = filepath.Dir(root)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A failure on the root entry itself is fatal: the scan cannot
			// proceed at all, so propagate it as a terminal error (captured
			// by the caller) instead of silently producing an empty scan.
			// Errors deeper in the tree are per-entry and skippable.
			if path == root {
				return fmt.Errorf("walk root %s: %w", root, err)
			}
			slog.Warn("directory read error", "path", path, "error", err)
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		switch s.classifyEntry(path, root, relBase, d, visited) {
		case entrySkipDir:
			return fs.SkipDir
		case entrySkip:
			return nil
		case entryScan:
		}

		return emitFileChunk(ctx, ch, path, relBase)
	})
}

// entryAction is the walk's decision for a single directory entry.
type entryAction int

const (
	// entryScan marks a candidate file that should be read and emitted.
	entryScan entryAction = iota
	// entrySkip ignores the entry; the walk continues normally.
	entrySkip
	// entrySkipDir skips the entry's whole subtree (fs.SkipDir).
	entrySkipDir
)

// classifyEntry decides what the walk should do with one directory entry. It
// applies, in order, the symlink guard, the version-control directory
// exclusion, the regular-file guard, the configured skip filters, and the
// cross-root deduplication. An accepted file is recorded in visited, so a file
// reachable from more than one root is scanned only once.
func (s *FilesystemSource) classifyEntry(path, root, relBase string, d fs.DirEntry, visited map[string]struct{}) entryAction {
	// Skip symlinks to avoid cycles and potential security issues.
	if d.Type()&fs.ModeSymlink != 0 {
		return entrySkip
	}

	if d.IsDir() {
		// Skip version-control metadata directories by default so the
		// Git object/pack store is never walked and read as plain files.
		// The explicit scan root is exempt, so `scan fs .git` still
		// works if a user genuinely targets it.
		if d.Name() == vcsDirName && path != root {
			return entrySkipDir
		}
		return entrySkip
	}

	// Only regular files are readable as content. Named pipes, sockets and
	// device files can block indefinitely on open/read, and symlinks are not
	// followed, so skip anything that is not a regular file. This also guards
	// a non-regular path passed directly as a scan target.
	if !d.Type().IsRegular() {
		return entrySkip
	}

	if s.shouldSkip(path, d, relBase) {
		return entrySkip
	}

	if _, seen := visited[path]; seen {
		return entrySkip
	}
	visited[path] = struct{}{}

	return entryScan
}

// emitFileChunk reads an accepted file and sends its contents as a chunk, with
// the reported path made relative to relBase. Neither a read failure (logged)
// nor binary content is terminal — both leave the walk running. The only error
// returned is the context's, when cancellation interrupts the send.
func emitFileChunk(ctx context.Context, ch chan<- source.Chunk, path, relBase string) error {
	data, err := readIfNotBinary(path)
	if err != nil {
		slog.Warn("file read error", "path", path, "error", err)
		return nil
	}
	if data == nil {
		// Binary content detected from the leading bytes; skip it.
		return nil
	}

	relPath, err := filepath.Rel(relBase, path)
	if err != nil {
		relPath = path
	}

	select {
	case ch <- source.Chunk{
		Data: data,
		SourceMetadata: finding.SourceMetadata{
			SourceType: "filesystem",
			FilePath:   relPath,
		},
	}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Err returns the first terminal error that aborted the filesystem walk, or nil
// if it completed normally. It must only be called after the channel returned by
// Chunks has been fully drained (closed).
func (s *FilesystemSource) Err() error {
	return s.err
}

func (s *FilesystemSource) shouldSkip(path string, d fs.DirEntry, relBase string) bool {
	// Skip auto-generated lock files (contain hashes that trigger false positives).
	if filter.IsSkippedFilename(path) {
		return true
	}

	// Extension check
	if filter.IsExcludedExtension(path, s.excludeExts) {
		return true
	}

	// Exclude path patterns
	relPath, err := filepath.Rel(relBase, path)
	if err == nil && filter.MatchesGlob(relPath, s.excludePaths) {
		return true
	}

	// File size check
	info, err := d.Info()
	if err != nil {
		return true
	}
	if info.Size() > s.maxFileSize || info.Size() == 0 {
		return true
	}

	return false
}

// readIfNotBinary reads path, returning its full contents. It first reads a
// bounded leading prefix (binaryPeekSize) and checks it for binary content
// before reading the remainder of the file, so binary files are never fully
// buffered just to be discarded. It returns a nil slice (with a nil error)
// when the file is detected as binary.
func readIfNotBinary(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	peek := make([]byte, binaryPeekSize)
	n, err := io.ReadFull(f, peek)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	peek = peek[:n]

	if filter.IsBinaryFile(peek) {
		return nil, nil
	}

	rest, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if len(rest) == 0 {
		return peek, nil
	}
	return append(peek, rest...), nil
}

// Package gcs provides a Google Cloud Storage bucket scan source.
//
// GCSSource implements the source.Source interface, listing and downloading
// objects from a GCS bucket and emitting them as chunks for secret scanning.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// defaultMaxFileSize is the maximum object size to scan (10 MB).
const defaultMaxFileSize int64 = 10 * 1024 * 1024

// validateTimeout bounds validation when the caller provides no earlier
// deadline. An earlier caller deadline or cancellation always wins.
const validateTimeout = 30 * time.Second

// gcsClient defines the subset of the GCS API used by GCSSource.
// This interface enables unit testing without real GCP calls.
type gcsClient interface {
	// Bucket returns a BucketHandle for the given bucket name.
	Bucket(name string) bucketHandle
	// Close releases resources held by the client.
	Close() error
}

// bucketHandle abstracts the operations on a single GCS bucket.
type bucketHandle interface {
	// Attrs retrieves the bucket's attributes.
	Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error)
	// Objects returns an iterator over objects matching the query.
	Objects(ctx context.Context, q *gcsstorage.Query) objectIterator
	// Object returns an ObjectHandle for the given key.
	Object(name string) objectHandle
}

// objectHandle abstracts read operations on a single GCS object.
type objectHandle interface {
	NewReader(ctx context.Context) (io.ReadCloser, error)
}

// objectIterator abstracts iteration over GCS object listings.
type objectIterator interface {
	Next() (*gcsstorage.ObjectAttrs, error)
}

// realClient wraps *gcsstorage.Client to satisfy the gcsClient interface.
type realClient struct {
	c *gcsstorage.Client
}

func (r *realClient) Bucket(name string) bucketHandle {
	return &realBucketHandle{b: r.c.Bucket(name)}
}
func (r *realClient) Close() error { return r.c.Close() }

type realBucketHandle struct {
	b *gcsstorage.BucketHandle
}

func (h *realBucketHandle) Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error) {
	return h.b.Attrs(ctx)
}

func (h *realBucketHandle) Objects(ctx context.Context, q *gcsstorage.Query) objectIterator {
	return h.b.Objects(ctx, q)
}

func (h *realBucketHandle) Object(name string) objectHandle {
	return &realObjectHandle{o: h.b.Object(name)}
}

type realObjectHandle struct {
	o *gcsstorage.ObjectHandle
}

func (o *realObjectHandle) NewReader(ctx context.Context) (io.ReadCloser, error) {
	return o.o.NewReader(ctx)
}

// GCSSource scans objects in a Google Cloud Storage bucket for leaked secrets.
type GCSSource struct {
	bucket       string
	prefix       string
	project      string
	maxFileSize  int64
	bufferSize   int
	excludePaths []string
	clientMu     sync.RWMutex
	client       gcsClient

	// err records the first terminal failure that aborted listing (client
	// initialization or an object-listing failure). It is written only by the
	// Chunks goroutine, before it closes the chunks channel, and read only via
	// Err after that channel has been drained; the channel close/drain is the
	// happens-before edge, so no extra synchronization is needed.
	err error
}

// New creates a new GCSSource for the given bucket.
// Use functional options to configure prefix filtering, max file size, etc.
func New(bucket string, opts ...Option) *GCSSource {
	s := &GCSSource{
		bucket:      bucket,
		maxFileSize: defaultMaxFileSize,
		bufferSize:  64,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type identifier.
func (s *GCSSource) Type() string {
	return "gcs"
}

// Err returns the first terminal error that aborted GCS listing, or nil if it
// completed normally. It must only be called after the channel returned by Chunks
// has been fully drained (closed).
func (s *GCSSource) Err() error {
	return s.err
}

// Close releases the GCS client. A close failure retains the client so callers
// can report the error and retry cleanup; successful repeated calls are no-ops.
func (s *GCSSource) Close() error {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.client == nil {
		return nil
	}
	if err := s.client.Close(); err != nil {
		return fmt.Errorf("gcs client close failed: %w", err)
	}
	s.client = nil
	return nil
}

// captureErr records the first terminal error that aborted chunk production. It
// is called only from the single Chunks goroutine, before close(ch), so a plain
// field write is safe (the channel close/drain publishes it to Err's reader).
// Context cancellation is never recorded because it is reported through the
// context, not Err. GCS API errors carry no credential material, so no additional
// sanitization is required here.
func (s *GCSSource) captureErr(err error) {
	if err == nil || s.err != nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	s.err = err
}

// Validate checks that the GCS bucket is accessible.
// It initializes the GCS client if not already set and checks bucket attributes.
func (s *GCSSource) Validate(ctx context.Context) error {
	if s.bucket == "" {
		return fmt.Errorf("gcs bucket name is required")
	}

	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()

	if err := s.ensureClient(ctx); err != nil {
		return fmt.Errorf("gcs client initialization failed: %w", err)
	}

	client, release := s.acquireClient()
	if client == nil {
		return fmt.Errorf("gcs client was closed before validation")
	}
	defer release()
	_, err := client.Bucket(s.bucket).Attrs(ctx)
	if err != nil {
		return fmt.Errorf("gcs bucket inaccessible %q: %w", s.bucket, err)
	}

	return nil
}

// Chunks lists objects in the GCS bucket and sends their contents over a channel.
// The channel is closed when all objects have been processed or the context is cancelled.
func (s *GCSSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		if err := s.ensureClient(ctx); err != nil {
			slog.Error("gcs client initialization failed", "error", err)
			s.captureErr(fmt.Errorf("gcs client initialization failed: %w", err))
			return
		}
		client, release := s.acquireClient()
		if client == nil {
			s.captureErr(fmt.Errorf("gcs client was closed before object listing"))
			return
		}
		defer release()

		s.listAndSendChunks(ctx, ch, client)
	}()
	return ch
}

// ensureClient initializes the GCS client if not already set.
func (s *GCSSource) ensureClient(ctx context.Context) error {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.client != nil {
		return nil
	}

	var opts []option.ClientOption
	if s.project != "" {
		opts = append(opts, option.WithQuotaProject(s.project))
	}

	c, err := gcsstorage.NewClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("gcs client creation failed: %w", err)
	}

	s.client = &realClient{c: c}
	return nil
}

func (s *GCSSource) acquireClient() (gcsClient, func()) {
	s.clientMu.RLock()
	if s.client == nil {
		s.clientMu.RUnlock()
		return nil, func() {}
	}
	return s.client, s.clientMu.RUnlock
}

// listAndSendChunks iterates through bucket objects and emits chunks.
func (s *GCSSource) listAndSendChunks(ctx context.Context, ch chan<- source.Chunk, client gcsClient) {
	query := &gcsstorage.Query{}
	if s.prefix != "" {
		query.Prefix = s.prefix
	}

	it := client.Bucket(s.bucket).Objects(ctx, query)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		attrs, err := it.Next()
		if err == iterator.Done {
			return
		}
		if err != nil {
			slog.Error("gcs list objects failed", "bucket", s.bucket, "error", err)
			s.captureErr(fmt.Errorf("gcs list objects failed for bucket %q: %w", s.bucket, err))
			return
		}

		key := attrs.Name

		// Skip objects that exceed the max file size.
		if attrs.Size > s.maxFileSize {
			slog.Debug("skipping large object", "key", key, "size", attrs.Size)
			continue
		}

		// Skip zero-byte objects.
		if attrs.Size == 0 {
			continue
		}

		// Skip binary extensions.
		if filter.IsExcludedExtension(key, nil) {
			slog.Debug("skipping excluded extension", "key", key)
			continue
		}

		// Skip objects matching exclude-path globs (relative key).
		if filter.MatchesGlob(key, s.excludePaths) {
			slog.Debug("skipping excluded path", "key", key)
			continue
		}

		data, err := s.downloadObject(ctx, client, key)
		if err != nil {
			slog.Warn("gcs object download failed", "key", key, "error", err)
			continue
		}
		if data == nil {
			// Object exceeded the size limit and was skipped.
			continue
		}

		// Skip binary content.
		if filter.IsBinaryFile(data) {
			slog.Debug("skipping binary object", "key", key)
			continue
		}

		filePath := s.bucket + "/" + key

		select {
		case ch <- source.Chunk{
			Data: data,
			SourceMetadata: finding.SourceMetadata{
				SourceType: "gcs",
				FilePath:   filePath,
			},
		}:
		case <-ctx.Done():
			return
		}
	}
}

// downloadObject fetches the content of a single GCS object.
func (s *GCSSource) downloadObject(ctx context.Context, client gcsClient, key string) ([]byte, error) {
	reader, err := client.Bucket(s.bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("open object %q: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Bound the read to guard against OOM/DoS from objects whose listed size
	// is stale, missing, or smaller than the actual body. Read one extra byte
	// so an object that exactly fills maxFileSize can be distinguished from one
	// that exceeds it.
	data, err := io.ReadAll(io.LimitReader(reader, s.maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read object %q: %w", key, err)
	}

	if int64(len(data)) > s.maxFileSize {
		slog.Debug("skipping oversize object", "key", key, "limit", s.maxFileSize)
		return nil, nil
	}

	return data, nil
}

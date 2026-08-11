// Package s3 provides an AWS S3 bucket scan source.
//
// S3Source implements the source.Source interface, listing and downloading
// objects from an S3 bucket and emitting them as chunks for secret scanning.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// defaultMaxFileSize is the maximum object size to scan (10 MB).
const defaultMaxFileSize int64 = 10 * 1024 * 1024

// validateTimeout bounds validation when the caller provides no earlier
// deadline. An earlier caller deadline or cancellation always wins.
const validateTimeout = 30 * time.Second

// s3Client defines the subset of the S3 API used by S3Source.
// This interface enables unit testing without real AWS calls.
type s3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// S3Source scans objects in an AWS S3 bucket for leaked secrets.
type S3Source struct {
	bucket       string
	prefix       string
	region       string
	maxFileSize  int64
	bufferSize   int
	excludePaths []string
	client       s3Client

	// err records the first terminal failure that aborted listing (client
	// initialization or a ListObjectsV2 failure). It is written only by the
	// Chunks goroutine, before it closes the chunks channel, and read only via
	// Err after that channel has been drained; the channel close/drain is the
	// happens-before edge, so no extra synchronization is needed.
	err error
}

// New creates a new S3Source for the given bucket.
// Use functional options to configure prefix filtering, max file size, etc.
func New(bucket string, opts ...Option) *S3Source {
	s := &S3Source{
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
func (s *S3Source) Type() string {
	return "s3"
}

// Err returns the first terminal error that aborted S3 listing, or nil if it
// completed normally. It must only be called after the channel returned by Chunks
// has been fully drained (closed).
func (s *S3Source) Err() error {
	return s.err
}

// captureErr records the first terminal error that aborted chunk production. It
// is called only from the single Chunks goroutine, before close(ch), so a plain
// field write is safe (the channel close/drain publishes it to Err's reader).
// Context cancellation is never recorded because it is reported through the
// context, not Err. AWS SDK errors carry no credential material, so no additional
// sanitization is required here.
func (s *S3Source) captureErr(err error) {
	if err == nil || s.err != nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	s.err = err
}

// Validate checks that the S3 bucket is accessible.
// It initializes the AWS client if not already set and performs a HeadBucket call.
func (s *S3Source) Validate(ctx context.Context) error {
	if s.bucket == "" {
		return fmt.Errorf("s3 bucket name is required")
	}

	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()

	if err := s.ensureClient(ctx); err != nil {
		return fmt.Errorf("s3 client initialization failed: %w", err)
	}

	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &s.bucket,
	})
	if err != nil {
		return fmt.Errorf("s3 bucket inaccessible %q: %w", s.bucket, err)
	}

	return nil
}

// Chunks lists objects in the S3 bucket and sends their contents over a channel.
// The channel is closed when all objects have been processed or the context is cancelled.
func (s *S3Source) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		if err := s.ensureClient(ctx); err != nil {
			slog.Error("s3 client initialization failed", "error", err)
			s.captureErr(fmt.Errorf("s3 client initialization failed: %w", err))
			return
		}

		s.listAndSendChunks(ctx, ch)
	}()
	return ch
}

// ensureClient initializes the AWS S3 client if not already set.
func (s *S3Source) ensureClient(ctx context.Context) error {
	if s.client != nil {
		return nil
	}

	var cfgOpts []func(*awsconfig.LoadOptions) error
	if s.region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(s.region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return fmt.Errorf("aws config load failed: %w", err)
	}

	s.client = s3.NewFromConfig(cfg)
	return nil
}

// listAndSendChunks paginates through bucket objects and emits chunks.
// Pagination is handled manually via ContinuationToken so the method works
// with both the real S3 client and the test mock (s3Client interface).
func (s *S3Source) listAndSendChunks(ctx context.Context, ch chan<- source.Chunk) {
	var continuationToken *string

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		input := &s3.ListObjectsV2Input{
			Bucket:            &s.bucket,
			ContinuationToken: continuationToken,
		}
		if s.prefix != "" {
			input.Prefix = &s.prefix
		}

		page, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			slog.Error("s3 list objects failed", "bucket", s.bucket, "error", err)
			s.captureErr(fmt.Errorf("s3 list objects failed for bucket %q: %w", s.bucket, err))
			return
		}

		for _, obj := range page.Contents {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if obj.Key == nil {
				continue
			}

			key := *obj.Key

			// Skip objects that exceed the max file size.
			if obj.Size != nil && *obj.Size > s.maxFileSize {
				slog.Debug("skipping large object", "key", key, "size", *obj.Size)
				continue
			}

			// Skip zero-byte objects.
			if obj.Size != nil && *obj.Size == 0 {
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

			data, err := s.downloadObject(ctx, key)
			if err != nil {
				slog.Warn("s3 object download failed", "key", key, "error", err)
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
					SourceType: "s3",
					FilePath:   filePath,
				},
			}:
			case <-ctx.Done():
				return
			}
		}

		// Check if there are more pages.
		if page.IsTruncated != nil && *page.IsTruncated && page.NextContinuationToken != nil {
			continuationToken = page.NextContinuationToken
		} else {
			return
		}
	}
}

// downloadObject fetches the content of a single S3 object.
func (s *S3Source) downloadObject(ctx context.Context, key string) ([]byte, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("get object %q: %w", key, err)
	}
	defer func() { _ = output.Body.Close() }()

	// Bound the read to guard against OOM/DoS from objects whose listed size
	// is stale, missing, or smaller than the actual body. Read one extra byte
	// so an object that exactly fills maxFileSize can be distinguished from one
	// that exceeds it.
	data, err := io.ReadAll(io.LimitReader(output.Body, s.maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read object %q: %w", key, err)
	}

	if int64(len(data)) > s.maxFileSize {
		slog.Debug("skipping oversize object", "key", key, "limit", s.maxFileSize)
		return nil, nil
	}

	return data, nil
}

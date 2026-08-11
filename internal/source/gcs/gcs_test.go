package gcs

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"

	"github.com/HodeTech/leakwatch/internal/source"
)

// mockGCSClient implements the gcsClient interface for testing.
type mockGCSClient struct {
	buckets    map[string]*mockBucketHandle
	closed     bool
	closeErr   error
	closeCalls int
}

func (m *mockGCSClient) Bucket(name string) bucketHandle {
	if bh, ok := m.buckets[name]; ok {
		return bh
	}
	return &mockBucketHandle{name: name, notFound: true}
}

func (m *mockGCSClient) Close() error {
	m.closeCalls++
	if m.closeErr != nil {
		return m.closeErr
	}
	m.closed = true
	return nil
}

// mockBucketHandle implements the bucketHandle interface for testing.
type mockBucketHandle struct {
	name             string
	notFound         bool
	objects          []*gcsstorage.ObjectAttrs
	data             map[string]string
	attrsBlock       bool
	attrsDeadline    time.Time
	attrsHasDeadline bool
	readerStarted    chan struct{}
}

func (b *mockBucketHandle) Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error) {
	b.attrsDeadline, b.attrsHasDeadline = ctx.Deadline()
	if b.attrsBlock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if b.notFound {
		return nil, fmt.Errorf("bucket not found")
	}
	return &gcsstorage.BucketAttrs{Name: b.name}, nil
}

func (b *mockBucketHandle) Objects(_ context.Context, q *gcsstorage.Query) objectIterator {
	var filtered []*gcsstorage.ObjectAttrs
	for _, obj := range b.objects {
		if q != nil && q.Prefix != "" && !strings.HasPrefix(obj.Name, q.Prefix) {
			continue
		}
		filtered = append(filtered, obj)
	}
	return &mockObjectIterator{objects: filtered}
}

func (b *mockBucketHandle) Object(name string) objectHandle {
	content := ""
	if b.data != nil {
		content = b.data[name]
	}
	return &mockObjectHandle{content: content, readerStarted: b.readerStarted}
}

// mockObjectHandle implements the objectHandle interface for testing.
type mockObjectHandle struct {
	content       string
	readerStarted chan struct{}
}

func (o *mockObjectHandle) NewReader(_ context.Context) (io.ReadCloser, error) {
	if o.readerStarted != nil {
		select {
		case o.readerStarted <- struct{}{}:
		default:
		}
	}
	return io.NopCloser(strings.NewReader(o.content)), nil
}

// mockObjectIterator implements the objectIterator interface for testing.
type mockObjectIterator struct {
	objects []*gcsstorage.ObjectAttrs
	idx     int
}

func (it *mockObjectIterator) Next() (*gcsstorage.ObjectAttrs, error) {
	if it.idx >= len(it.objects) {
		return nil, iterator.Done
	}
	obj := it.objects[it.idx]
	it.idx++
	return obj, nil
}

func TestGCSSource_Type_ReturnsGCS(t *testing.T) {
	s := New("my-bucket")
	assert.Equal(t, "gcs", s.Type())
}

func TestGCSSource_New_DefaultValues(t *testing.T) {
	s := New("my-bucket")
	assert.Equal(t, "my-bucket", s.bucket)
	assert.Equal(t, int64(10*1024*1024), s.maxFileSize)
	assert.Equal(t, 64, s.bufferSize)
	assert.Empty(t, s.prefix)
}

func TestGCSSource_New_WithOptions(t *testing.T) {
	s := New(
		"my-bucket",
		WithPrefix("logs/"),
		WithMaxFileSize(5*1024*1024),
		WithBufferSize(32),
		WithProject("my-project"),
	)
	assert.Equal(t, "logs/", s.prefix)
	assert.Equal(t, int64(5*1024*1024), s.maxFileSize)
	assert.Equal(t, 32, s.bufferSize)
	assert.Equal(t, "my-project", s.project)
}

func TestWithMaxFileSize_InvalidValue_NoOp(t *testing.T) {
	s := New("my-bucket")
	original := s.maxFileSize

	WithMaxFileSize(0)(s)
	assert.Equal(t, original, s.maxFileSize)

	WithMaxFileSize(-1)(s)
	assert.Equal(t, original, s.maxFileSize)
}

func TestWithMaxFileSize_ValidValue_Applied(t *testing.T) {
	s := New("my-bucket", WithMaxFileSize(1024))
	assert.Equal(t, int64(1024), s.maxFileSize)
}

func TestGCSSource_Validate_EmptyBucket_ReturnsError(t *testing.T) {
	s := New("")
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket name is required")
}

func TestGCSSource_Validate_AccessibleBucket_ReturnsNil(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {name: "my-bucket"},
		},
	}
	s := New("my-bucket")
	s.client = mock
	assert.NoError(t, s.Validate(context.Background()))
}

func TestGCSSource_Validate_AppliesDefaultDeadline(t *testing.T) {
	bucket := &mockBucketHandle{name: "my-bucket"}
	mock := &mockGCSClient{buckets: map[string]*mockBucketHandle{"my-bucket": bucket}}
	s := New("my-bucket")
	s.client = mock
	started := time.Now()

	require.NoError(t, s.Validate(context.Background()))
	require.True(t, bucket.attrsHasDeadline)
	assert.WithinDuration(t, started.Add(validateTimeout), bucket.attrsDeadline, time.Second)
}

func TestGCSSource_Validate_CallerDeadlineCancelsRequest(t *testing.T) {
	bucket := &mockBucketHandle{name: "my-bucket", attrsBlock: true}
	mock := &mockGCSClient{buckets: map[string]*mockBucketHandle{"my-bucket": bucket}}
	s := New("my-bucket")
	s.client = mock
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()

	err := s.Validate(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
	assert.WithinDuration(t, started.Add(20*time.Millisecond), bucket.attrsDeadline, 50*time.Millisecond)
}

func TestGCSSource_Validate_InaccessibleBucket_ReturnsError(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{},
	}
	s := New("missing-bucket")
	s.client = mock
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inaccessible")
	require.NoError(t, s.Close())
	assert.True(t, mock.closed, "a client created before validation failure must remain closeable")
}

func TestGCSSource_Chunks_SendsTextObjects(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "config.yaml", Size: 20},
					{Name: "secret.txt", Size: 15},
				},
				data: map[string]string{
					"config.yaml": "api_key: test123",
					"secret.txt":  "password=hunter2",
				},
			},
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 2)
	assert.Contains(t, chunks, "my-bucket/config.yaml")
	assert.Contains(t, chunks, "my-bucket/secret.txt")
}

func TestGCSSource_Chunks_SkipsBinaryExtensions(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "code.go", Size: 20},
					{Name: "image.png", Size: 20},
				},
				data: map[string]string{
					"code.go": "package main",
				},
			},
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/code.go", chunks[0])
}

func TestGCSSource_Chunks_SkipsLargeObjects(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "small.txt", Size: 100},
					{Name: "big.txt", Size: 20 * 1024 * 1024},
				},
				data: map[string]string{
					"small.txt": "small content",
				},
			},
		},
	}

	s := New("my-bucket", WithMaxFileSize(1024*1024))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/small.txt", chunks[0])
}

func TestGCSSource_Chunks_SkipsBinaryContent(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "text.txt", Size: 11},
					{Name: "binary.dat", Size: 11},
				},
				data: map[string]string{
					"text.txt":   "hello world",
					"binary.dat": "hello\x00world",
				},
			},
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/text.txt", chunks[0])
}

func TestGCSSource_Chunks_ContextCancellation(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "a.txt", Size: 5},
					{Name: "b.txt", Size: 5},
					{Name: "c.txt", Size: 5},
				},
				data: map[string]string{
					"a.txt": "aaa",
					"b.txt": "bbb",
					"c.txt": "ccc",
				},
			},
		},
	}

	s := New("my-bucket", WithBufferSize(1))
	s.client = mock

	ctx, cancel := context.WithCancel(context.Background())
	ch := s.Chunks(ctx)

	// Read one chunk then cancel.
	<-ch
	cancel()

	// Drain the channel; it must close.
	count := 0
	for range ch {
		count++
	}
	assert.Less(t, count, 3)
}

func TestGCSSource_Chunks_SourceMetadata_Format(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "path/to/file.env", Size: 10},
				},
				data: map[string]string{
					"path/to/file.env": "SECRET=abc",
				},
			},
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunk source.Chunk
	for chunk = range s.Chunks(ctx) {
	}

	assert.Equal(t, "gcs", chunk.SourceMetadata.SourceType)
	assert.Equal(t, "my-bucket/path/to/file.env", chunk.SourceMetadata.FilePath)
}

func TestGCSSource_Chunks_BoundsReadToMaxFileSize(t *testing.T) {
	// The listed size understates the real body so the listing-based size
	// check passes, but the bounded read must still drop the oversize object.
	bigBody := strings.Repeat("A", 2048)
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "small.txt", Size: 5},
					{Name: "liar.txt", Size: 5},
				},
				data: map[string]string{
					"small.txt": "hello",
					"liar.txt":  bigBody,
				},
			},
		},
	}

	s := New("my-bucket", WithMaxFileSize(1024))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/small.txt", chunks[0])
}

func TestGCSSource_DownloadObject_AtLimit_NotSkipped(t *testing.T) {
	body := strings.Repeat("A", 1024)
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				data: map[string]string{"exact.txt": body},
			},
		},
	}
	s := New("my-bucket", WithMaxFileSize(1024))
	s.client = mock

	data, err := s.downloadObject(context.Background(), mock, "exact.txt")
	require.NoError(t, err)
	assert.Len(t, data, 1024)
}

func TestGCSSource_Chunks_WithExcludePaths_FiltersObjects(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "src/app.go", Size: 10},
					{Name: "vendor/lib.go", Size: 10},
					{Name: "test/data.txt", Size: 10},
				},
				data: map[string]string{
					"src/app.go":    "package app",
					"vendor/lib.go": "package lib",
					"test/data.txt": "fixture",
				},
			},
		},
	}

	s := New("my-bucket", WithExcludePaths([]string{"vendor/**", "test/*"}))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/src/app.go", chunks[0])
}

func TestGCSSource_New_WithExcludePaths_StoresPatterns(t *testing.T) {
	s := New("my-bucket", WithExcludePaths([]string{"a/**", "b"}))
	assert.Equal(t, []string{"a/**", "b"}, s.excludePaths)
}

func TestGCSSource_CallerOwnsClientCloseAfterChunksComplete(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "a.txt", Size: 5},
				},
				data: map[string]string{"a.txt": "aaaaa"},
			},
		},
	}

	s := New("my-bucket")
	s.client = mock

	for range s.Chunks(context.Background()) {
		// Drain the channel so Chunks' goroutine releases its client lease.
	}

	assert.False(t, mock.closed, "chunk production must not compete with the CLI cleanup owner")
	require.NoError(t, s.Close())
	assert.True(t, mock.closed)
	assert.Nil(t, s.client, "successful close must make later cleanup idempotent")
}

func TestGCSSource_CloseWaitsForCancelledProducerAndClosesOnce(t *testing.T) {
	readerStarted := make(chan struct{}, 1)
	mock := &mockGCSClient{buckets: map[string]*mockBucketHandle{
		"my-bucket": {
			name:          "my-bucket",
			objects:       []*gcsstorage.ObjectAttrs{{Name: "secret.txt", Size: 6}},
			data:          map[string]string{"secret.txt": "secret"},
			readerStarted: readerStarted,
		},
	}}
	s := New("my-bucket")
	s.bufferSize = 0
	s.client = mock
	ctx, cancel := context.WithCancel(context.Background())
	chunks := s.Chunks(ctx)

	select {
	case <-readerStarted:
	case <-time.After(time.Second):
		t.Fatal("producer did not begin object download")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while producer still held the client lease: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	for range chunks {
	}
	require.NoError(t, <-closed)
	assert.Equal(t, 1, mock.closeCalls)
	require.NoError(t, s.Close())
	assert.Equal(t, 1, mock.closeCalls)
}

func TestGCSSource_Close_FailureRemainsRetryable(t *testing.T) {
	closeErr := fmt.Errorf("synthetic close failure")
	mock := &mockGCSClient{buckets: map[string]*mockBucketHandle{}, closeErr: closeErr}
	s := New("my-bucket")
	s.client = mock

	err := s.Close()
	require.ErrorIs(t, err, closeErr)
	assert.Same(t, mock, s.client)
	assert.Equal(t, 1, mock.closeCalls)

	mock.closeErr = nil
	require.NoError(t, s.Close())
	assert.Nil(t, s.client)
	assert.Equal(t, 2, mock.closeCalls)
	require.NoError(t, s.Close())
	assert.Equal(t, 2, mock.closeCalls, "an already-closed source must be a no-op")
}

func TestGCSSource_Chunks_WithPrefix_FiltersObjects(t *testing.T) {
	mock := &mockGCSClient{
		buckets: map[string]*mockBucketHandle{
			"my-bucket": {
				name: "my-bucket",
				objects: []*gcsstorage.ObjectAttrs{
					{Name: "logs/app.log", Size: 10},
					{Name: "config/app.yaml", Size: 10},
				},
				data: map[string]string{
					"config/app.yaml": "key: value",
				},
			},
		},
	}

	s := New("my-bucket", WithPrefix("config/"))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/config/app.yaml", chunks[0])
}

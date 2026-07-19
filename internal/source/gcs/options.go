// Package gcs provides a Google Cloud Storage bucket scan source.
package gcs

// Option configures a GCSSource.
type Option func(*GCSSource)

// WithPrefix limits the scan to objects matching the given key prefix.
func WithPrefix(prefix string) Option {
	return func(s *GCSSource) {
		s.prefix = prefix
	}
}

// WithMaxFileSize sets the maximum object size to download and scan.
// Objects larger than this value are skipped.
// Values less than or equal to zero are ignored, preserving the default.
func WithMaxFileSize(size int64) Option {
	return func(s *GCSSource) {
		if size <= 0 {
			return
		}
		s.maxFileSize = size
	}
}

// WithBufferSize sets the channel buffer size for the chunk channel.
func WithBufferSize(size int) Option {
	return func(s *GCSSource) {
		if size > 0 {
			s.bufferSize = size
		}
	}
}

// WithProject sets the GCP project ID for the storage client.
func WithProject(project string) Option {
	return func(s *GCSSource) {
		s.project = project
	}
}

// WithExcludePaths sets glob patterns for object names to exclude from scanning.
// Patterns are matched against each object's name (the object's path within the
// bucket), mirroring filesystem.WithExcludePaths semantics.
func WithExcludePaths(patterns []string) Option {
	return func(s *GCSSource) {
		s.excludePaths = patterns
	}
}

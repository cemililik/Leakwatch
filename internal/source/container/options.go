package container

// Option configures a ContainerSource.
type Option func(*ContainerSource)

// WithMaxFileSize sets the maximum file size to extract from layers.
// Values less than or equal to zero are ignored.
func WithMaxFileSize(size int64) Option {
	return func(s *ContainerSource) {
		if size <= 0 {
			return
		}
		s.maxFileSize = size
	}
}

// WithMaxLayerSize sets the maximum number of decompressed bytes read from a
// single layer, guarding against decompression-bomb layers with an extreme
// compression ratio. Values less than or equal to zero are ignored.
func WithMaxLayerSize(size int64) Option {
	return func(s *ContainerSource) {
		if size <= 0 {
			return
		}
		s.maxLayerSize = size
	}
}

// WithMaxImageSize sets the maximum number of decompressed bytes read across
// all of an image's layers, bounding total decompression work. Values less
// than or equal to zero are ignored.
func WithMaxImageSize(size int64) Option {
	return func(s *ContainerSource) {
		if size <= 0 {
			return
		}
		s.maxImageSize = size
	}
}

// WithBufferSize sets the chunk channel buffer size.
// Values less than or equal to zero are ignored.
func WithBufferSize(size int) Option {
	return func(s *ContainerSource) {
		if size <= 0 {
			return
		}
		s.bufferSize = size
	}
}

// WithExcludePaths sets glob patterns for layer file paths to exclude from
// scanning. Patterns are matched against each file's cleaned, slash-based path
// within the layer, mirroring filesystem.WithExcludePaths semantics.
func WithExcludePaths(patterns []string) Option {
	return func(s *ContainerSource) {
		s.excludePaths = patterns
	}
}

// Package source defines scan source interfaces.
package source

import (
	"context"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Source represents a data source to be scanned.
// Each source type (Git, filesystem, container) implements this interface.
type Source interface {
	// Type returns the source type identifier (e.g., "git", "filesystem", "container").
	Type() string

	// Chunks streams scannable data chunks over a channel.
	//
	// The returned channel is closed exactly once, when chunk production has
	// finished: either after the source has streamed every chunk to normal
	// completion, or after it aborts early on a terminal failure (see Err), or
	// after the given context is cancelled. Callers must drain the channel until
	// it is closed; only then is the outcome of the scan known.
	Chunks(ctx context.Context) <-chan Chunk

	// Err returns the first terminal (fatal) error that aborted or prevented
	// chunk production — a clone/open failure, an authentication error, a
	// listing/pull error, a decompression-limit trip, a directory-walk failure,
	// and so on — or nil if the source streamed to normal completion.
	//
	// A nil Err with zero chunks means the target was genuinely empty; a non-nil
	// Err means the scan failed and any absence of findings must NOT be treated
	// as a clean result. Context cancellation is reported through the context,
	// not here, so a cancelled scan leaves Err nil.
	//
	// Err is only valid to call AFTER the channel returned by Chunks has been
	// fully drained (closed). The channel close is the happens-before edge that
	// publishes the terminal error the source records before closing the channel,
	// so no additional synchronization is required for this single read. Calling
	// Err before the channel closes is a data race.
	Err() error

	// Validate checks that the source is accessible and valid.
	Validate() error
}

// Chunk is the smallest unit of data to be scanned.
type Chunk struct {
	// Data is the raw content to scan.
	Data []byte

	// SourceMetadata describes where the chunk originated from.
	SourceMetadata finding.SourceMetadata
}

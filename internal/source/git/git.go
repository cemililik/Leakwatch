// Package git provides a Git repository scan source.
package git

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// maxSeenEntries is the upper bound for the blob deduplication map.
// When reached, deduplication is disabled to prevent unbounded memory growth.
const maxSeenEntries = 1_000_000

// minAbbrevHashLen is the minimum number of hex characters accepted for an
// abbreviated since-commit hash, matching Git's own default minimum.
const minAbbrevHashLen = 4

// fullHashLen is the length in hex characters of a full SHA-1 commit hash.
const fullHashLen = 40

// credentialRE matches a "scheme://user[:password]@" userinfo segment so it can
// be stripped from library error strings that re-embed the raw clone URL. It is
// a defense-in-depth complement to the verbatim target replacement in
// sanitizeCloneError, guarding against go-git re-encoding the userinfo.
var credentialRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@`)

// GitSource is a Git repository-based scan source.
type GitSource struct {
	target         string // Local path or remote URL
	displayTarget  string // Credential-stripped form of target, safe for output/logs
	repo           *git.Repository
	bufferSize     int
	since          *time.Time
	sinceCommit    string
	branch         string
	depth          int
	maxFileSize    int64
	excludePaths   []string
	tmpDir         string // Temporary directory for cloned repos
	resolvedBranch string // Cached branch resolution
	removeAll      func(string) error

	// err records the first terminal failure that aborted history production
	// (start-commit resolution, git log, or the history walk). It is written
	// only by the Chunks goroutine, before it closes the chunks channel, and
	// read only via Err after that channel has been drained; the channel
	// close/drain is the happens-before edge, so no extra synchronization is
	// needed. Every value stored here is credential-sanitized (see captureErr).
	err error
}

// New creates a new GitSource.
func New(target string, opts ...Option) *GitSource {
	s := &GitSource{
		target:        target,
		displayTarget: SafeDisplayURL(target),
		bufferSize:    64,
		maxFileSize:   10 * 1024 * 1024,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type.
func (s *GitSource) Type() string {
	return "git"
}

// Validate checks that the Git repository is accessible and opens/clones it.
// When --branch is set on a local target it verifies the branch exists, and
// when --since-commit is set it verifies the given commit is an ancestor of the
// walk's starting point; otherwise the diff-based walk would silently fall back
// to scanning the entire history or an unintended branch.

func (s *GitSource) Validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remote, cloneTarget, err := classifyGitTarget(s.target)
	if err != nil {
		return fmt.Errorf("invalid git target %s: %w", s.displayTarget, err)
	}
	if remote {
		if err := s.cloneRemote(ctx, cloneTarget); err != nil {
			return err
		}
	} else if err := s.openLocal(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if s.branch != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := s.resolveStartHash(); err != nil {
			return err
		}
	}

	if s.sinceCommit != "" {
		if err := s.validateSinceCommit(ctx); err != nil {
			return err
		}
	}

	return nil
}

// validateSinceCommit verifies that the configured since-commit exists and is an
// ancestor of the walk's starting commit (the configured branch tip, or HEAD).
// Returning an explicit error prevents the diff-based scan from silently
// degrading into a full-history scan.
func (s *GitSource) validateSinceCommit(ctx context.Context) error {
	sinceCommitObj, err := s.resolveCommitHash(ctx, s.sinceCommit)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	startHash, err := s.resolveStartHash()
	if err != nil {
		return fmt.Errorf("failed to resolve start commit for since-commit check: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	startCommit, err := s.repo.CommitObject(startHash)
	if err != nil {
		return fmt.Errorf("failed to resolve start commit for since-commit check: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if sinceCommitObj.Hash == startCommit.Hash {
		return nil
	}

	isAncestor, err := isAncestorContext(ctx, sinceCommitObj, startCommit)
	if err != nil {
		return fmt.Errorf("failed to check ancestry of since-commit %q: %w", s.sinceCommit, err)
	}
	if !isAncestor {
		return fmt.Errorf("since-commit %q is not an ancestor of %q", s.sinceCommit, startCommit.Hash.String())
	}

	return nil
}

// resolveCommitHash resolves a full (40-character) or abbreviated commit hash to
// a commit object. Full SHAs are looked up directly; shorter hex prefixes are
// resolved by scanning the object store for a unique match, so the documented
// `--since-commit abc1234` short-hash usage works rather than silently producing
// a wrong zero-padded hash via plumbing.NewHash.
func (s *GitSource) resolveCommitHash(ctx context.Context, ref string) (*object.Commit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalized, full, err := normalizeCommitHashReference(ref)
	if err != nil {
		return nil, err
	}
	if full {
		return s.resolveFullCommitHash(ctx, normalized)
	}
	return s.resolveAbbreviatedCommitHash(ctx, normalized)
}

func normalizeCommitHashReference(ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if len(ref) < minAbbrevHashLen {
		return "", false, fmt.Errorf("since-commit %q is too short: provide at least %d hex characters or a full 40-character SHA", ref, minAbbrevHashLen)
	}
	if len(ref) > fullHashLen || !isHexString(ref) {
		return "", false, fmt.Errorf("since-commit %q is not a valid commit hash", ref)
	}
	return ref, len(ref) == fullHashLen, nil
}

func (s *GitSource) resolveFullCommitHash(ctx context.Context, ref string) (*object.Commit, error) {
	commit, err := s.repo.CommitObject(plumbing.NewHash(ref))
	if err != nil {
		return nil, fmt.Errorf("since-commit %q not found: %w", ref, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return commit, nil
}

func (s *GitSource) resolveAbbreviatedCommitHash(ctx context.Context, ref string) (*object.Commit, error) {
	// Deliberately NOT go-git's Repository.ResolveRevision: it resolves a hash
	// prefix by collecting every candidate and returning the first that resolves,
	// with no ambiguity signal (there is no ErrAmbiguousRevision in go-git). For a
	// secret scanner, silently starting the history walk from an arbitrary one of
	// several matching commits could skip real history, so we scan for the prefix
	// ourselves and report ambiguity as an error — matching git's own strictness.
	// The full-hash fast path above avoids this walk in the common case.
	lower := strings.ToLower(ref)
	iter, err := s.repo.CommitObjects()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate commits for since-commit lookup: %w", err)
	}
	defer iter.Close()

	var (
		match     *object.Commit
		ambiguous bool
	)
	err = iter.ForEach(func(c *object.Commit) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasPrefix(c.Hash.String(), lower) {
			return nil
		}
		if match != nil && match.Hash != c.Hash {
			ambiguous = true
			return io.EOF // stop early
		}
		match = c
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to scan commits for since-commit lookup: %w", err)
	}
	if ambiguous {
		return nil, fmt.Errorf("since-commit %q is ambiguous: matches multiple commits", ref)
	}
	if match == nil {
		return nil, fmt.Errorf("since-commit %q not found", ref)
	}
	return match, nil
}

func isAncestorContext(ctx context.Context, ancestor, descendant *object.Commit) (bool, error) {
	iter := object.NewCommitPreorderIter(descendant, nil, nil)
	defer iter.Close()
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		commit, err := iter.Next()
		switch {
		case errors.Is(err, io.EOF):
			return false, nil
		case err != nil:
			return false, err
		case commit.Hash == ancestor.Hash:
			return true, nil
		}
	}
}

// resolveStartHash returns the commit hash the history walk should start from.
// When --branch is configured it resolves that branch's local ref (so the flag
// steers which commits are scanned, not just the metadata label); otherwise it
// falls back to HEAD.
func (s *GitSource) resolveStartHash() (plumbing.Hash, error) {
	if s.branch != "" {
		ref, err := s.repo.Reference(plumbing.NewBranchReferenceName(s.branch), true)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("failed to resolve branch %q: %w", s.branch, err)
		}
		return ref.Hash(), nil
	}
	headRef, err := s.repo.Head()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to resolve HEAD: %w", err)
	}
	return headRef.Hash(), nil
}

// Close cleans up temporary resources. For cloned repositories, it removes
// the temporary directory.
func (s *GitSource) Close() error {
	if s.tmpDir != "" {
		removeAll := s.removeAll
		if removeAll == nil {
			removeAll = os.RemoveAll
		}
		if err := removeAll(s.tmpDir); err != nil {
			return fmt.Errorf("failed to remove temp directory %s: %w", s.tmpDir, err)
		}
		s.tmpDir = ""
	}
	return nil
}

func (s *GitSource) isRemote() bool {
	remote, _, err := classifyGitTarget(s.target)
	return err == nil && remote
}

// classifyGitTarget distinguishes the supported network transports from local
// paths without relying on case-sensitive string prefixes. URI schemes are
// case-insensitive under RFC 3986; unsupported schemes fail closed instead of
// being reinterpreted as local filesystem paths. Windows drive-letter paths
// remain local even when this code is cross-compiled on another platform.
func classifyGitTarget(target string) (remote bool, normalized string, err error) {
	if strings.HasPrefix(target, "git@") {
		return true, target, nil
	}
	if len(target) >= 3 && target[1] == ':' &&
		((target[0] >= 'a' && target[0] <= 'z') || (target[0] >= 'A' && target[0] <= 'Z')) &&
		(target[2] == '/' || target[2] == '\\') {
		return false, target, nil
	}

	// A colon is legal in a local Unix filename. Treat a target as a URI only
	// when it uses the explicit scheme:// form; SCP syntax was handled above.
	if !strings.Contains(target, "://") {
		return false, target, nil
	}
	parsed, parseErr := url.Parse(target)
	if parseErr != nil {
		return false, "", fmt.Errorf("malformed target")
	}
	if parsed.Scheme == "" {
		return false, target, nil
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ssh":
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		return true, parsed.String(), nil
	default:
		return false, "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}
}

func (s *GitSource) openLocal() error {
	info, err := os.Stat(s.target)
	if err != nil {
		return fmt.Errorf("failed to inspect git target %s: %w", s.displayTarget, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("git target %s is not a directory", s.displayTarget)
	}
	// DetectDotGit walks up parent directories to find the repository root,
	// matching real git tooling when pointed at a subdirectory of a repo.
	repo, err := git.PlainOpenWithOptions(s.target, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("failed to open git repository %s: %w", s.displayTarget, err)
	}
	s.repo = repo
	return nil
}

func (s *GitSource) cloneRemote(ctx context.Context, cloneTarget string) error {
	tmpDir, err := os.MkdirTemp("", "leakwatch-clone-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	// Own the directory immediately so every failure path can clean it through
	// Close and a failed cleanup remains retryable by the caller.
	s.tmpDir = tmpDir

	cloneOpts := &git.CloneOptions{
		URL:      cloneTarget,
		Progress: nil,
	}

	if s.depth > 0 {
		cloneOpts.Depth = s.depth
	}

	if s.branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(s.branch)
		cloneOpts.SingleBranch = true
	}

	slog.Info("cloning remote repository", "url", s.displayTarget, "tmpDir", tmpDir)

	repo, err := git.PlainCloneContext(ctx, tmpDir, false, cloneOpts)
	if err != nil {
		// go-git's HTTP transport and endpoint layers re-embed the raw
		// user:password@host userinfo from the clone URL into their error
		// strings, so the raw err must never be wrapped with %w. Sanitize it
		// first so no credential can reach errors.Unwrap chains, stderr, or CI
		// logs.
		var cloneErr error
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Preserve cancellation identity so the CLI maps an interrupted clone
			// to exit 3. The context error itself contains no clone credential.
			cloneErr = ctxErr
		} else {
			cloneErr = fmt.Errorf("failed to clone git repository %s: %w",
				s.displayTarget, sanitizeCloneError(err, s.target, s.displayTarget))
		}
		if cleanupErr := s.Close(); cleanupErr != nil {
			return errors.Join(cloneErr, cleanupErr)
		}
		return cloneErr
	}
	s.repo = repo
	return nil
}

// Err returns the first terminal error that aborted Git history production, or
// nil if it completed normally. Any error stored here has been run through
// sanitizeCloneError, so it can never carry raw clone credentials. It must only
// be called after the channel returned by Chunks has been fully drained (closed).
func (s *GitSource) Err() error {
	return s.err
}

// captureErr records the first terminal error that aborted chunk production. It
// is called only from the single Chunks goroutine, before close(ch), so a plain
// field write is safe (the channel close/drain publishes it to Err's reader).
// The error is always sanitized so no clone credential can enter Err's message
// or its unwrap chain; context cancellation is never recorded because it is
// reported through the context, not Err.
func (s *GitSource) captureErr(err error) {
	if err == nil || s.err != nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	s.err = sanitizeCloneError(err, s.target, s.displayTarget)
}

// sanitizeCloneError returns a new, flat error whose message has any embedded
// clone credentials stripped. It first replaces the verbatim credentialed
// target with its safe form, then strips any remaining "scheme://userinfo@"
// segment (covering the case where go-git re-encoded the userinfo differently
// from the raw target). The result is a plain errors.New so the raw error — and
// any credential substring it carries — never enters the returned error's
// unwrap chain.
func sanitizeCloneError(err error, rawTarget, safeTarget string) error {
	msg := err.Error()
	if rawTarget != "" && rawTarget != safeTarget {
		msg = strings.ReplaceAll(msg, rawTarget, safeTarget)
	}
	msg = credentialRE.ReplaceAllString(msg, "$1")
	return errors.New(msg)
}

// isHexString reports whether s consists solely of hexadecimal digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// SafeDisplayURL returns a credential-stripped form of raw that is safe to put
// in logs, output metadata, error messages, and the scan summary. Any user-info
// portion (the "user:password@" part of a URL) is removed so no secret is ever
// surfaced.
//
// The returned value is the clean URL with no noisy suffix, so it can be stored
// verbatim in a metadata field. When the URL cannot be parsed, the credential
// between "://" and "@" is masked on a best-effort basis; non-URL targets (for
// example local paths) are returned unchanged.
func SafeDisplayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Best-effort: mask anything between :// and @
		if idx := strings.Index(raw, "@"); idx != -1 {
			if schemeEnd := strings.Index(raw, "://"); schemeEnd != -1 {
				return raw[:schemeEnd+3] + "***@" + raw[idx+1:]
			}
		}
		return raw
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

// Chunks sends Git commit history files as chunks over a channel.
func (s *GitSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		if s.sinceCommit != "" {
			s.chunksSinceCommit(ctx, ch)
			return
		}

		s.chunksFullHistory(ctx, ch)
	}()
	return ch
}

// chunksFullHistory scans the entire reachable history from the configured
// branch tip (or HEAD), diffing each commit against its first parent so every
// blob is attributed to the commit that introduced it.
func (s *GitSource) chunksFullHistory(ctx context.Context, ch chan<- source.Chunk) {
	startHash, err := s.resolveStartHash()
	if err != nil {
		slog.Error("failed to resolve start commit", "error", err)
		s.captureErr(fmt.Errorf("failed to resolve start commit: %w", err))
		return
	}
	s.walkCommits(ctx, ch, startHash, plumbing.ZeroHash)
}

// chunksSinceCommit scans commits between the configured since-commit
// (exclusive) and the branch tip / HEAD (inclusive), diffing each commit against
// its parent.
func (s *GitSource) chunksSinceCommit(ctx context.Context, ch chan<- source.Chunk) {
	sinceCommitObj, err := s.resolveCommitHash(ctx, s.sinceCommit)
	if err != nil {
		slog.Error("since-commit resolution failed", "commit", s.sinceCommit, "error", err)
		s.captureErr(fmt.Errorf("since-commit resolution failed: %w", err))
		return
	}

	startHash, err := s.resolveStartHash()
	if err != nil {
		slog.Error("failed to resolve start commit", "error", err)
		s.captureErr(fmt.Errorf("failed to resolve start commit: %w", err))
		return
	}

	s.walkCommits(ctx, ch, startHash, sinceCommitObj.Hash)
}

// walkCommits walks history newest-first from `from`, diffing each commit
// against its first parent (an empty tree for the root commit) and emitting the
// added/modified files. When `stop` is non-zero the walk halts as soon as it is
// reached (exclusive). The configured --since cutoff, when set, is honored in
// both full-history and since-commit modes.
func (s *GitSource) walkCommits(ctx context.Context, ch chan<- source.Chunk, from, stop plumbing.Hash) {
	iter, err := s.repo.Log(&git.LogOptions{
		From:  from,
		Order: git.LogOrderCommitterTime,
		Since: s.since,
	})
	if err != nil {
		slog.Error("git log failed", "error", err)
		s.captureErr(fmt.Errorf("git log failed: %w", err))
		return
	}
	defer iter.Close()

	seen := make(map[string]bool) // content+path key -> already processed
	seenFull := false             // true when seen map hit the limit
	commitCount := 0

	err = iter.ForEach(func(c *object.Commit) error {
		if stop != plumbing.ZeroHash && c.Hash == stop {
			return io.EOF // reached the since-commit boundary
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		commitCount++
		return s.emitCommitChanges(ctx, ch, c, seen, &seenFull)
	})

	if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		slog.Error("commit history scan failed", "error", err)
		s.captureErr(fmt.Errorf("commit history scan failed: %w", err))
	}

	slog.Info("git scan completed", "commits", commitCount, "blobs", len(seen))
}

// emitCommitChanges diffs a commit against its first parent and emits a chunk
// for each added/modified file that passes the size, binary, and exclusion
// filters.
func (s *GitSource) emitCommitChanges(
	ctx context.Context,
	ch chan<- source.Chunk,
	c *object.Commit,
	seen map[string]bool,
	seenFull *bool,
) error {
	commitTree, changes, ok := commitDiff(c)
	if !ok {
		return nil
	}

	cs := &commitScan{
		tree: commitTree,
		meta: finding.SourceMetadata{
			SourceType: "git",
			Repository: s.displayTarget,
			Commit:     c.Hash.String(),
			Author:     c.Author.Name,
			Email:      c.Author.Email,
			Date:       c.Author.When,
			Branch:     s.resolveBranch(),
		},
		seen:     seen,
		seenFull: seenFull,
	}

	for _, change := range changes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := s.emitChangedFile(ctx, ch, cs, change); err != nil {
			return err
		}
	}
	return nil
}

// commitScan carries the state every changed file of a single commit shares:
// the commit's tree, the finding metadata template (every field but FilePath),
// and the cross-commit blob deduplication state.
type commitScan struct {
	tree     *object.Tree
	meta     finding.SourceMetadata
	seen     map[string]bool
	seenFull *bool
}

// commitDiff resolves a commit's tree and the changes it introduced relative to
// its first parent. The root commit is diffed against an empty tree so its files
// are reported as introduced, and an unreadable parent degrades to that same
// empty-tree diff rather than dropping the commit. ok is false only when the
// commit's own tree or the diff itself cannot be produced; the failure has
// already been logged and the commit is skipped.
func commitDiff(c *object.Commit) (*object.Tree, object.Changes, bool) {
	commitTree, err := c.Tree()
	if err != nil {
		slog.Warn("failed to get commit tree", "commit", shortHash(c.Hash), "error", err)
		return nil, nil, false
	}

	// Diff against the first parent; the root commit diffs against an empty tree
	// so its files are reported as introduced.
	parentTree := &object.Tree{}
	if c.NumParents() > 0 {
		parent, err := c.Parent(0)
		if err != nil {
			slog.Warn("failed to get parent commit", "commit", shortHash(c.Hash), "error", err)
		} else if pt, err := parent.Tree(); err != nil {
			slog.Warn("failed to get parent tree", "commit", shortHash(c.Hash), "error", err)
		} else {
			parentTree = pt
		}
	}

	changes, err := parentTree.Diff(commitTree)
	if err != nil {
		slog.Warn("failed to diff commit against parent", "commit", shortHash(c.Hash), "error", err)
		return nil, nil, false
	}

	return commitTree, changes, true
}

// emitChangedFile emits a chunk for one changed file of a commit. A deletion,
// an unresolvable blob, oversized or binary content, a filtered path, and an
// already-scanned blob are all skipped without error. The only error returned is
// the context's, when cancellation interrupts the send.
func (s *GitSource) emitChangedFile(
	ctx context.Context,
	ch chan<- source.Chunk,
	cs *commitScan,
	change *object.Change,
) error {
	file, ok := s.scannableBlob(cs.tree, change)
	if !ok {
		return nil
	}

	if !markBlobSeen(change, cs.seen, cs.seenFull) {
		return nil
	}

	content, err := readBlob(file, s.maxFileSize)
	if err != nil {
		slog.Warn("failed to read file contents", "file", change.To.Name, "error", err)
		return nil
	}

	meta := cs.meta
	meta.FilePath = change.To.Name

	select {
	case ch <- source.Chunk{
		Data:           content,
		SourceMetadata: meta,
	}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// scannableBlob resolves the post-change blob of one diff entry and applies the
// per-file filters. ok is false when the entry must be skipped: a deletion, a
// blob missing from the commit tree, content over the size limit, binary
// content, a generated lock file, or a match against the configured
// exclude-path globs.
func (s *GitSource) scannableBlob(commitTree *object.Tree, change *object.Change) (*object.File, bool) {
	// Only scan added/modified files.
	if change.To.Name == "" {
		return nil, false // Deleted file.
	}

	file, err := commitTree.File(change.To.Name)
	if err != nil {
		return nil, false
	}

	if file.Size > s.maxFileSize {
		return nil, false
	}

	isBinary, err := file.IsBinary()
	if err != nil {
		slog.Debug("binary check failed", "file", change.To.Name, "error", err)
	}
	if isBinary {
		return nil, false
	}

	// Skip auto-generated lock files.
	if filter.IsSkippedFilename(change.To.Name) {
		return nil, false
	}

	// Skip files matching exclude-path globs (relative path).
	if filter.MatchesGlob(change.To.Name, s.excludePaths) {
		return nil, false
	}

	return file, true
}

// markBlobSeen records a blob for deduplication and reports whether it should be
// scanned. Only blobs that would actually be emitted reach this point. Keying on
// content+path ensures two distinct files with identical content are both
// reported, while a re-added identical blob at the same path is scanned once.
// Once the map reaches maxSeenEntries, deduplication is disabled (seenFull) to
// prevent unbounded memory growth and every later blob is accepted.
func markBlobSeen(change *object.Change, seen map[string]bool, seenFull *bool) bool {
	if *seenFull {
		return true
	}

	blobKey := change.To.TreeEntry.Hash.String() + "\x00" + change.To.Name
	if seen[blobKey] {
		return false
	}
	seen[blobKey] = true
	if len(seen) >= maxSeenEntries {
		slog.Warn("blob deduplication map reached limit, disabling dedup",
			"limit", maxSeenEntries)
		*seenFull = true
	}
	return true
}

// readBlob reads a file blob's bytes directly into a []byte, avoiding the
// Reader → bytes.Buffer → string → []byte round-trip of object.File.Contents.
// The caller has already verified the blob size against limit, so the
// LimitReader guards only against unexpectedly large streams.
func readBlob(f *object.File, limit int64) ([]byte, error) {
	reader, err := f.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to open blob reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}
	return data, nil
}

// shortHash returns the abbreviated (8-character) form of a commit hash for
// logging.
func shortHash(h plumbing.Hash) string {
	return h.String()[:8]
}

// resolveBranch returns the current branch name, caching the result after
// the first resolution to avoid repeated Head() calls. For a detached HEAD it
// returns a short-commit reference rather than the bare string "HEAD".
func (s *GitSource) resolveBranch() string {
	if s.branch != "" {
		return s.branch
	}
	if s.resolvedBranch != "" {
		return s.resolvedBranch
	}
	headRef, err := s.repo.Head()
	if err != nil {
		return ""
	}
	if headRef.Name() == plumbing.HEAD {
		// Detached HEAD (common in CI checkouts of a specific commit/PR): there
		// is no branch name, so surface a short commit reference instead.
		s.resolvedBranch = "detached@" + shortHash(headRef.Hash())
	} else {
		s.resolvedBranch = headRef.Name().Short()
	}
	return s.resolvedBranch
}

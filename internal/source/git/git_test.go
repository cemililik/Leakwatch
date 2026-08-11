package git

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cancelAfterErrChecks struct {
	context.Context
	remaining int
}

func (c *cancelAfterErrChecks) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

// initTestRepo creates a temporary git repository for testing.
func initTestRepo(t *testing.T, files map[string]string) (string, *gogit.Repository) {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := wt.Add(name)
		require.NoError(t, err)
	}

	_, err = wt.Commit("initial commit", &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "Test Author",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	return dir, repo
}

// addCommit adds a new commit to the test repository.
func addCommit(t *testing.T, dir string, repo *gogit.Repository, files map[string]string, msg string) string {
	t.Helper()
	wt, err := repo.Worktree()
	require.NoError(t, err)

	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		_, err := wt.Add(name)
		require.NoError(t, err)
	}

	hash, err := wt.Commit(msg, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "Test Author",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
	return hash.String()
}

func TestGitSource_Type(t *testing.T) {
	s := New("/tmp/repo")
	assert.Equal(t, "git", s.Type())
}

func TestGitSource_Validate_ValidRepo(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"README.md": "hello"})

	s := New(dir)
	assert.NoError(t, s.Validate(context.Background()))
}

func TestGitSource_Validate_NonExistentRepo(t *testing.T) {
	s := New("/nonexistent/repo")
	assert.Error(t, s.Validate(context.Background()))
}

func TestGitSource_Validate_NotAGitRepo(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	assert.Error(t, s.Validate(context.Background()))
}

func TestGitSource_Chunks_ReadsCommitHistory(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{
		"config.env": "AKIAIOSFODNN7EXAMPLE",
		"main.go":    "package main",
	})

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 2)
	assert.Contains(t, chunks, "config.env")
	assert.Contains(t, chunks, "main.go")
}

func TestGitSource_Chunks_IncludesCommitMetadata(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{
		"secret.txt": "api_key=test123456789012345678",
	})

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	for chunk := range s.Chunks(ctx) {
		assert.Equal(t, "git", chunk.SourceMetadata.SourceType)
		assert.Equal(t, dir, chunk.SourceMetadata.Repository)
		assert.NotEmpty(t, chunk.SourceMetadata.Commit)
		assert.Equal(t, "Test Author", chunk.SourceMetadata.Author)
		assert.Equal(t, "test@example.com", chunk.SourceMetadata.Email)
		assert.False(t, chunk.SourceMetadata.Date.IsZero())
		assert.Equal(t, "secret.txt", chunk.SourceMetadata.FilePath)
	}
}

func TestGitSource_Chunks_MultipleCommits(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{
		"file1.txt": "content1",
	})

	addCommit(t, dir, repo, map[string]string{
		"file2.txt": "content2",
	}, "second commit")

	addCommit(t, dir, repo, map[string]string{
		"file3.txt": "content3",
	}, "third commit")

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	seen := make(map[string]bool)
	for chunk := range s.Chunks(ctx) {
		seen[chunk.SourceMetadata.FilePath] = true
	}

	// Due to blob deduplication each unique file appears once.
	assert.True(t, seen["file1.txt"])
	assert.True(t, seen["file2.txt"])
	assert.True(t, seen["file3.txt"])
}

func TestGitSource_Chunks_SinceCommit(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{
		"old.txt": "old content",
	})

	// Get the first commit hash.
	headRef, err := repo.Head()
	require.NoError(t, err)
	sinceHash := headRef.Hash().String()

	// Add new commits.
	addCommit(t, dir, repo, map[string]string{
		"new1.txt": "AKIAIOSFODNN7EXAMPLE",
	}, "new commit 1")

	addCommit(t, dir, repo, map[string]string{
		"new2.txt": "secret data",
	}, "new commit 2")

	s := New(dir, WithSinceCommit(sinceHash))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	// Only files after since-commit should appear.
	assert.Contains(t, files, "new1.txt")
	assert.Contains(t, files, "new2.txt")
	assert.NotContains(t, files, "old.txt")
}

func TestGitSource_Validate_SinceCommitNotFound_ReturnsError(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"a.txt": "content"})

	// A well-formed but non-existent commit hash.
	s := New(dir, WithSinceCommit("0123456789abcdef0123456789abcdef01234567"))
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGitSource_Validate_SinceCommitNotAncestor_ReturnsError(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"base.txt": "base"})

	// Record the base commit and the default branch (HEAD currently points here).
	headRef, err := repo.Head()
	require.NoError(t, err)
	baseHash := headRef.Hash()
	mainBranch := headRef.Name()

	// Create a divergent branch off the base commit and commit there.
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&gogit.CheckoutOptions{
		Hash:   baseHash,
		Branch: "refs/heads/sidebranch",
		Create: true,
	}))
	sideHash := addCommit(t, dir, repo, map[string]string{"side.txt": "side"}, "side commit")

	// Switch HEAD back to the main branch and advance it independently.
	require.NoError(t, wt.Checkout(&gogit.CheckoutOptions{Branch: mainBranch}))
	addCommit(t, dir, repo, map[string]string{"main2.txt": "main2"}, "main second commit")

	// sideHash lives only on sidebranch, so it is not an ancestor of HEAD (main).
	s := New(dir, WithSinceCommit(sideHash))
	err = s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an ancestor")
}

func TestGitSource_Validate_SinceCommitIsAncestor_ReturnsNil(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"a.txt": "content"})

	headRef, err := repo.Head()
	require.NoError(t, err)
	baseHash := headRef.Hash().String()

	addCommit(t, dir, repo, map[string]string{"b.txt": "more"}, "second commit")

	s := New(dir, WithSinceCommit(baseHash))
	assert.NoError(t, s.Validate(context.Background()))
}

func TestGitSource_Validate_SinceCommitEqualsHead_ReturnsNil(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"a.txt": "content"})

	headRef, err := repo.Head()
	require.NoError(t, err)
	headHash := headRef.Hash().String()

	s := New(dir, WithSinceCommit(headHash))
	assert.NoError(t, s.Validate(context.Background()))
}

func TestGitSource_Chunks_WithExcludePaths_SkipsMatching(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{
		"src/app.go":     "package app",
		"vendor/lib.go":  "package lib",
		"node_modules/x": "junk",
	})

	s := New(dir, WithExcludePaths([]string{"vendor/**", "node_modules/**"}))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "src/app.go")
	assert.NotContains(t, files, "vendor/lib.go")
	assert.NotContains(t, files, "node_modules/x")
}

func TestGitSource_New_WithExcludePaths_StoresPatterns(t *testing.T) {
	s := New("/tmp/repo", WithExcludePaths([]string{"a/**", "b"}))
	assert.Equal(t, []string{"a/**", "b"}, s.excludePaths)
}

func TestGitSource_Chunks_WithSince(t *testing.T) {
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Old commit with a past date.
	oldTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "old.txt"), []byte("old content"), 0o644))
	_, err = wt.Add("old.txt")
	require.NoError(t, err)
	_, err = wt.Commit("old commit", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "t@t.com", When: oldTime},
		Committer: &object.Signature{Name: "Test", Email: "t@t.com", When: oldTime},
	})
	require.NoError(t, err)

	// Cutoff: 2025-01-01
	cutoff := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// New commit after cutoff.
	newTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new.txt"), []byte("new content"), 0o644))
	_, err = wt.Add("new.txt")
	require.NoError(t, err)
	_, err = wt.Commit("new commit", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "t@t.com", When: newTime},
		Committer: &object.Signature{Name: "Test", Email: "t@t.com", When: newTime},
	})
	require.NoError(t, err)

	s := New(dir, WithSince(cutoff))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "new.txt")
}

func TestGitSource_Err_SuccessfulChunks_ReturnsNil(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"README.md": "hello"})

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	for range s.Chunks(context.Background()) {
	}

	assert.NoError(t, s.Err(), "a fully-streamed history must report no terminal error")
}

func TestGitSource_Err_HistoryWalkFailure_ReturnsError(t *testing.T) {
	// A freshly-initialized repository has no commits, so HEAD does not resolve.
	// Validate(ctx) succeeds (the repo opens), but the history walk in Chunks fails
	// to resolve a start commit — a terminal error that must be reported via Err
	// rather than silently yielding a clean, empty scan.
	dir := t.TempDir()
	_, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	var count int
	for range s.Chunks(context.Background()) {
		count++
	}

	assert.Zero(t, count, "an unborn-HEAD repo produces no chunks")
	require.Error(t, s.Err(), "the failed history walk must be reported via Err")
	assert.Contains(t, s.Err().Error(), "resolve start commit")
}

func TestGitSource_Err_CapturedErrorIsCredentialSanitized(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"
	credentialedURL := "https://user:" + fakeToken + "@github.com/org/repo.git"

	// captureErr is the single choke point every terminal git error flows
	// through; it must strip any embedded clone credential (and drop it from the
	// unwrap chain) before the error becomes visible via Err. A go-git error that
	// re-embeds the credentialed clone URL is the worst case this guards against.
	s := New(credentialedURL)
	underlying := fmt.Errorf("git log failed: unable to reach %s", credentialedURL)
	s.captureErr(underlying)

	require.Error(t, s.Err())
	assert.NotContains(t, s.Err().Error(), fakeToken,
		"a captured git error must never contain the raw credential")
	assert.NotContains(t, s.Err().Error(), "user:", "userinfo must not survive")
	assert.NotErrorIs(t, s.Err(), underlying,
		"the raw (credentialed) error must not remain reachable via the unwrap chain")

	// First-error-wins: a later terminal error must not overwrite the first.
	s.captureErr(fmt.Errorf("second error"))
	assert.NotContains(t, s.Err().Error(), "second error")
}

func TestGitSource_Chunks_ContextCancellation(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{
		"file.txt": "content",
	})

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	count := 0
	for range s.Chunks(ctx) {
		count++
	}
	// Channel should close with zero or very few chunks.
	assert.LessOrEqual(t, count, 1)
}

func TestGitSource_Chunks_SkipsLargeFiles(t *testing.T) {
	bigContent := make([]byte, 1024)
	for i := range bigContent {
		bigContent[i] = 'A'
	}

	dir, _ := initTestRepo(t, map[string]string{
		"small.txt": "small",
		"big.txt":   string(bigContent),
	})

	s := New(dir, WithMaxFileSize(512))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "small.txt")
	assert.NotContains(t, files, "big.txt")
}

func TestGitSource_IsRemote(t *testing.T) {
	tests := []struct {
		target   string
		expected bool
	}{
		{"https://github.com/org/repo.git", true},
		{"HTTPS://github.com/org/repo.git", true},
		{"http://github.com/org/repo.git", true},
		{"SSH://git@github.com/org/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"ssh://git@github.com/org/repo.git", true},
		{"/local/path/to/repo", false},
		{"./relative/repo", false},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			s := New(tt.target)
			assert.Equal(t, tt.expected, s.isRemote())
		})
	}
}

func TestClassifyGitTarget_RejectsUnsupportedScheme(t *testing.T) {
	remote, normalized, err := classifyGitTarget("ftp://user:wave9-canary@example.test/repo.git")
	require.Error(t, err)
	assert.False(t, remote)
	assert.Empty(t, normalized)
	assert.NotContains(t, err.Error(), "wave9-canary")
}

func TestClassifyGitTarget_LocalPathContainingColonRemainsLocal(t *testing.T) {
	remote, normalized, err := classifyGitTarget("repo:with-colon")
	require.NoError(t, err)
	assert.False(t, remote)
	assert.Equal(t, "repo:with-colon", normalized)
}

func TestGitSource_Validate_NonexistentRelativeTargetDoesNotOpenParentRepo(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"README.md": "parent repo"})
	t.Chdir(dir)

	s := New("definitely-not-existing-wave9")
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to inspect git target")
	assert.Nil(t, s.repo, "a typo must never silently select and scan the parent repository")
}

func TestGitSource_Validate_LocalFileTargetIsRejected(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"README.md": "parent repo"})
	s := New(filepath.Join(dir, "README.md"))

	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
	assert.Nil(t, s.repo)
}

func TestGitSource_Validate_UppercaseHTTPSSchemeNeverLeaksUserinfo(t *testing.T) {
	const canary = "wave9-canary-not-a-secret"
	s := New("HTTPS://user:" + canary + "@127.0.0.1:1/repo.git")

	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, err.Error(), "user:")
	assert.Empty(t, s.tmpDir, "failed remote clone must clean its temporary directory")
}

func TestGitSource_Close_RemovesTmpDir(t *testing.T) {
	// Simulate a cloned repo by setting tmpDir manually.
	tmpDir := t.TempDir()

	// Create a marker file to verify cleanup.
	marker := filepath.Join(tmpDir, "marker.txt")
	require.NoError(t, os.WriteFile(marker, []byte("test"), 0o644))

	s := &GitSource{
		tmpDir: tmpDir,
	}

	// Close should remove the directory.
	err := s.Close()
	require.NoError(t, err)

	// Verify the directory no longer exists.
	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err), "tmpDir should be removed after Close()")

	// Calling Close again should be a no-op.
	err = s.Close()
	assert.NoError(t, err)
}

func TestGitSource_Close_NoTmpDir(t *testing.T) {
	s := New("/some/local/repo")

	// Close on a non-cloned source should be a no-op.
	err := s.Close()
	assert.NoError(t, err)
}

func TestGitSource_Close_FailedCleanupRemainsRetryable(t *testing.T) {
	tmpDir := t.TempDir()
	cleanupErr := errors.New("synthetic cleanup failure")
	s := &GitSource{
		tmpDir:    tmpDir,
		removeAll: func(string) error { return cleanupErr },
	}

	err := s.Close()
	require.ErrorIs(t, err, cleanupErr)
	assert.Equal(t, tmpDir, s.tmpDir, "failed cleanup must retain ownership for a retry")

	s.removeAll = os.RemoveAll
	require.NoError(t, s.Close())
	assert.Empty(t, s.tmpDir)
	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err))
}

func TestGitSource_ResolveCommitHash_CancellationStopsEnumeration(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"base.txt": "base"})
	head, err := repo.Head()
	require.NoError(t, err)
	basePrefix := head.Hash().String()[:8]
	for i := range 20 {
		addCommit(t, dir, repo, map[string]string{
			fmt.Sprintf("file-%d.txt", i): fmt.Sprintf("content-%d", i),
		}, fmt.Sprintf("commit-%d", i))
	}

	s := New(dir)
	require.NoError(t, s.openLocal())
	ctx := &cancelAfterErrChecks{Context: context.Background(), remaining: 2}

	_, err = s.resolveCommitHash(ctx, basePrefix)
	require.ErrorIs(t, err, context.Canceled)
}

func TestIsAncestorContext_CancellationStopsHistoryWalk(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"base.txt": "base"})
	baseRef, err := repo.Head()
	require.NoError(t, err)
	base, err := repo.CommitObject(baseRef.Hash())
	require.NoError(t, err)

	for i := range 20 {
		addCommit(t, dir, repo, map[string]string{
			fmt.Sprintf("history-%d.txt", i): fmt.Sprintf("content-%d", i),
		}, fmt.Sprintf("history-%d", i))
	}
	headRef, err := repo.Head()
	require.NoError(t, err)
	head, err := repo.CommitObject(headRef.Hash())
	require.NoError(t, err)

	ctx := &cancelAfterErrChecks{Context: context.Background(), remaining: 2}
	_, err = isAncestorContext(ctx, base, head)
	require.ErrorIs(t, err, context.Canceled)
}

func TestGitSource_Validate_RemoteCloneCancellationIsPromptAndCleansUp(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-requestStarted:
		default:
			close(requestStarted)
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	s := New(server.URL + "/repo.git")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Validate(ctx) }()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("clone did not start an HTTP request")
	}
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, s.tmpDir, "cancelled clone must clean up its temporary directory")
	case <-time.After(2 * time.Second):
		t.Fatal("remote validation did not stop promptly after cancellation")
	}
}

func TestSafeDisplayURL_StripsCredentials(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "https with user and password",
			input:    "https://user:password@github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "https without credentials",
			input:    "https://github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "https with token as userinfo",
			input:    "https://" + fakeToken + "@github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "https with user and token",
			input:    "https://user:" + fakeToken + "@github.com/org/repo.git",
			expected: "https://github.com/org/repo.git",
		},
		{
			name:     "local path is unchanged",
			input:    "/local/path/to/repo",
			expected: "/local/path/to/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeDisplayURL(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.NotContains(t, result, fakeToken, "credential must not appear in display URL")
			// The returned value must be a clean URL with no noisy suffix that
			// would pollute a metadata field.
			assert.NotContains(t, result, "redacted")
			assert.NotContains(t, result, "(")
		})
	}
}

func TestSafeDisplayURL_ParseFailure_MasksCredential(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "FAKEtoken1234567890"
	// A control character makes url.Parse fail, exercising the best-effort path.
	input := "https://user:" + fakeToken + "@ho\x7fst/repo.git"

	result := SafeDisplayURL(input)

	assert.NotContains(t, result, fakeToken, "credential must not appear after best-effort masking")
	assert.Contains(t, result, "***@")
}

func TestSanitizeCloneError_StripsVerbatimCredential(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"
	rawTarget := "https://user:" + fakeToken + "@github.com/org/repo.git"
	safeTarget := SafeDisplayURL(rawTarget)

	// Simulate go-git/stdlib wrapping the credentialed URL verbatim in its error.
	underlying := fmt.Errorf("Get %q: dial tcp: lookup host: no such host", rawTarget)
	sanitized := sanitizeCloneError(underlying, rawTarget, safeTarget)

	assert.NotContains(t, sanitized.Error(), fakeToken, "token must not survive in the clone error")
	assert.NotContains(t, sanitized.Error(), "user:", "userinfo must not survive in the clone error")
	// The sanitized error must be flat: the raw error (and its credential) must
	// never remain reachable via the unwrap chain.
	assert.NotErrorIs(t, sanitized, underlying)
}

func TestSanitizeCloneError_StripsReEncodedUserinfo(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"
	safeTarget := "https://github.com/org/repo.git"

	// go-git's HTTP transport may re-embed userinfo in a form that does not match
	// the raw target verbatim (e.g. token-as-username on an unexpected status);
	// the regex fallback must still strip it.
	underlying := fmt.Errorf(
		`unexpected requesting "https://x-access-token:%s@github.com/org/repo.git/info/refs?service=git-upload-pack" status code: 429`,
		fakeToken,
	)
	sanitized := sanitizeCloneError(underlying, "https://unrelated@example.com", safeTarget)

	assert.NotContains(t, sanitized.Error(), fakeToken, "re-encoded token must be stripped")
	assert.NotContains(t, sanitized.Error(), "x-access-token", "re-encoded username must be stripped")
}

func TestGitSource_New_SetsCredentialFreeDisplayTarget(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"
	target := "https://user:" + fakeToken + "@github.com/org/repo.git"

	s := New(target)

	// The real target is retained for cloning, but the display form is clean.
	assert.Equal(t, target, s.target)
	assert.Equal(t, "https://github.com/org/repo.git", s.displayTarget)
	assert.NotContains(t, s.displayTarget, fakeToken)
}

func TestGitSource_Chunks_RepositoryMetadataHasNoCredential(t *testing.T) {
	// fakeToken is a non-secret placeholder used only to prove redaction.
	const fakeToken = "ghp_FAKEtoken1234567890"

	dir, _ := initTestRepo(t, map[string]string{"README.md": "hello"})

	// Build a source pointed at the local repo, but override the display target
	// as if it had been created from a credentialed remote URL. We set target to
	// the local dir so Validate/Chunks can read it, and displayTarget to the
	// credential-stripped remote form that should appear in metadata.
	s := New(dir)
	s.displayTarget = SafeDisplayURL("https://user:" + fakeToken + "@github.com/org/repo.git")
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var sawChunk bool
	for chunk := range s.Chunks(ctx) {
		sawChunk = true
		assert.Equal(t, "https://github.com/org/repo.git", chunk.SourceMetadata.Repository)
		assert.NotContains(t, chunk.SourceMetadata.Repository, fakeToken,
			"SourceMetadata.Repository must not contain the credential")
	}
	assert.True(t, sawChunk, "expected at least one chunk")
}

func TestGitSource_Chunks_FullHistory_AttributesIntroducingCommit(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{
		"config.txt": "AKIAIOSFODNN7EXAMPLE",
	})

	// Record the commit that introduced config.txt.
	headRef, err := repo.Head()
	require.NoError(t, err)
	introHash := headRef.Hash().String()

	// Later commits that never touch config.txt (its blob is unchanged since).
	addCommit(t, dir, repo, map[string]string{"a.txt": "aaa"}, "second commit")
	addCommit(t, dir, repo, map[string]string{"b.txt": "bbb"}, "third commit")

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var configCommit string
	for chunk := range s.Chunks(ctx) {
		if chunk.SourceMetadata.FilePath == "config.txt" {
			configCommit = chunk.SourceMetadata.Commit
		}
	}

	assert.Equal(t, introHash, configCommit,
		"config.txt must be attributed to the commit that introduced it, not the newest commit")
}

func TestGitSource_Chunks_FullHistory_ReportsBothPathsForIdenticalContent(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{
		"first.txt": "duplicate-content-value",
	})

	// A second, distinct file with byte-for-byte identical content.
	addCommit(t, dir, repo, map[string]string{
		"second.txt": "duplicate-content-value",
	}, "add duplicate content under a different path")

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "first.txt")
	assert.Contains(t, files, "second.txt",
		"two distinct files with identical content must both be reported, not deduped away")
}

func TestGitSource_Chunks_Branch_ScansRequestedBranchLocally(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"base.txt": "base"})

	headRef, err := repo.Head()
	require.NoError(t, err)
	baseHash := headRef.Hash()
	mainBranch := headRef.Name()

	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Create a feature branch off base and commit a feature-only file.
	require.NoError(t, wt.Checkout(&gogit.CheckoutOptions{
		Hash:   baseHash,
		Branch: "refs/heads/feature",
		Create: true,
	}))
	addCommit(t, dir, repo, map[string]string{"feature-only.txt": "feature content"}, "feature commit")

	// Return HEAD to main and commit a main-only file.
	require.NoError(t, wt.Checkout(&gogit.CheckoutOptions{Branch: mainBranch}))
	addCommit(t, dir, repo, map[string]string{"main-only.txt": "main content"}, "main commit")

	s := New(dir, WithBranch("feature"))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	var branchLabel string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
		branchLabel = chunk.SourceMetadata.Branch
	}

	assert.Contains(t, files, "feature-only.txt", "--branch feature must actually scan the feature branch")
	assert.NotContains(t, files, "main-only.txt", "--branch feature must not scan HEAD/main")
	assert.Equal(t, "feature", branchLabel)
}

func TestGitSource_Validate_Branch_NotFound_ReturnsError(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"a.txt": "content"})

	s := New(dir, WithBranch("does-not-exist"))
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

func TestGitSource_Validate_SinceCommit_AbbreviatedHash_Resolves(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"a.txt": "content"})

	headRef, err := repo.Head()
	require.NoError(t, err)
	shortHash := headRef.Hash().String()[:8]

	addCommit(t, dir, repo, map[string]string{"b.txt": "more"}, "second commit")

	s := New(dir, WithSinceCommit(shortHash))
	require.NoError(t, s.Validate(context.Background()), "an abbreviated since-commit hash should resolve, not fail as 'not found'")

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "b.txt")
	assert.NotContains(t, files, "a.txt")
}

func TestGitSource_Validate_SinceCommit_TooShort_ReturnsClearError(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"a.txt": "content"})

	s := New(dir, WithSinceCommit("ab"))
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "since-commit")
	assert.Contains(t, err.Error(), "too short")
}

func TestGitSource_Validate_SinceCommit_NonHex_ReturnsClearError(t *testing.T) {
	dir, _ := initTestRepo(t, map[string]string{"a.txt": "content"})

	s := New(dir, WithSinceCommit("zzzzzzz"))
	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid commit hash")
}

func TestGitSource_Chunks_SinceCommitWithSince_HonorsSince(t *testing.T) {
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	commitAt := func(name, content string, when time.Time) plumbing.Hash {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
		_, err := wt.Add(name)
		require.NoError(t, err)
		h, err := wt.Commit("c-"+name, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "T", Email: "t@t.com", When: when},
			Committer: &object.Signature{Name: "T", Email: "t@t.com", When: when},
		})
		require.NoError(t, err)
		return h
	}

	base := commitAt("base.txt", "base", time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC))
	commitAt("bfile.txt", "bbb", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	commitAt("cfile.txt", "ccc", time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))

	// since-commit excludes base; --since additionally drops the 2024 commit.
	cutoff := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(dir, WithSinceCommit(base.String()), WithSince(cutoff))
	require.NoError(t, s.Validate(context.Background()))

	ctx := context.Background()
	var files []string
	for chunk := range s.Chunks(ctx) {
		files = append(files, chunk.SourceMetadata.FilePath)
	}

	assert.Contains(t, files, "cfile.txt")
	assert.NotContains(t, files, "bfile.txt", "--since must still be honored when --since-commit is set")
	assert.NotContains(t, files, "base.txt")
}

func TestGitSource_ResolveBranch_DetachedHead_ReportsShortCommit(t *testing.T) {
	dir, repo := initTestRepo(t, map[string]string{"a.txt": "content"})

	headRef, err := repo.Head()
	require.NoError(t, err)
	baseHash := headRef.Hash()

	wt, err := repo.Worktree()
	require.NoError(t, err)
	// Detach HEAD directly at the commit (no Branch set).
	require.NoError(t, wt.Checkout(&gogit.CheckoutOptions{Hash: baseHash}))

	s := New(dir)
	require.NoError(t, s.Validate(context.Background()))

	branch := s.resolveBranch()
	assert.True(t, strings.HasPrefix(branch, "detached@"),
		"detached HEAD should report a detached@<short-sha> reference, got %q", branch)
	assert.NotEqual(t, "HEAD", branch)
}

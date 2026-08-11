// Package slack provides a Slack workspace scan source.
package slack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"golang.org/x/time/rate"

	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	// DefaultRateLimit matches Slack's lowest published conversations.history
	// contract for newly distributed non-Marketplace apps: one request/minute.
	// Marketplace and internal customer-built apps can raise it explicitly.
	DefaultRateLimit    = 1.0 / 60.0
	defaultBufferSize   = 100
	defaultMaxFileSize  = 10 * 1024 * 1024
	defaultHistoryLimit = 15
	validationTimeout   = 10 * time.Second
	slackRequestTimeout = 30 * time.Second

	// maxRateLimitRetries bounds how many consecutive HTTP 429 responses a
	// single page fetch will absorb before giving up, preventing an
	// unbounded retry loop against a workspace that never recovers.
	maxRateLimitRetries = 5

	// defaultRetryAfter is used when a *slack.RateLimitedError reports a
	// non-positive RetryAfter duration, as a safe fallback backoff.
	defaultRetryAfter     = time.Second
	maximumRetryAfterWait = 2 * time.Minute
)

// SlackSource scans messages in a Slack workspace for leaked secrets.
type SlackSource struct {
	token           string
	channels        []string
	excludeChannels []string
	since           time.Time
	includeDMs      bool
	includeFiles    bool
	maxFileSize     int64
	rateLimit       float64
	bufferSize      int
	client          slackClient
	newClient       func(token string) slackClient

	// err records the first terminal failure that aborted scanning (channel
	// listing / auth / pagination). It is written only by the Chunks goroutine,
	// before it closes the chunks channel, and read only via Err after that
	// channel has been drained; the channel close/drain is the happens-before
	// edge, so no extra synchronization is needed. Any value stored here has the
	// workspace token redacted (see captureErr).
	err error
}

// defaultNewClient creates a real Slack API client.
func defaultNewClient(token string) slackClient {
	return slack.New(token, slack.OptionHTTPClient(&http.Client{
		CheckRedirect: rejectSlackRedirect,
		Timeout:       slackRequestTimeout,
	}))
}

func rejectSlackRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// New creates a new SlackSource for the given workspace token.
// Use functional options to configure channel filtering, rate limits, etc.
func New(token string, opts ...Option) *SlackSource {
	s := &SlackSource{
		token:        token,
		includeDMs:   false,
		includeFiles: false,
		maxFileSize:  defaultMaxFileSize,
		rateLimit:    DefaultRateLimit,
		bufferSize:   defaultBufferSize,
		newClient:    defaultNewClient,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type identifier.
func (s *SlackSource) Type() string {
	return "slack"
}

// Err returns the first terminal error that aborted the Slack scan, or nil if it
// completed normally. Any error stored here has the workspace token redacted, so
// it can never leak the credential. It must only be called after the channel
// returned by Chunks has been fully drained (closed).
func (s *SlackSource) Err() error {
	return s.err
}

// captureErr records the first terminal error that aborted chunk production. It
// is called only from the single Chunks goroutine, before close(ch), so a plain
// field write is safe (the channel close/drain publishes it to Err's reader).
// As defense-in-depth against a client library that echoes the token, any
// occurrence of the workspace token is stripped from the stored message (and,
// when present, the error is flattened so the token cannot survive in the unwrap
// chain either). Context cancellation is never recorded because it is reported
// through the context, not Err.
func (s *SlackSource) captureErr(err error) {
	if err == nil || s.err != nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if s.token != "" && strings.Contains(err.Error(), s.token) {
		s.err = errors.New(strings.ReplaceAll(err.Error(), s.token, "***"))
		return
	}
	s.err = err
}

// Validate checks that the Slack token is valid by calling AuthTest. The
// operation is bounded even when the caller supplies no deadline, while an
// earlier caller deadline or cancellation always wins.
func (s *SlackSource) Validate(ctx context.Context) error {
	if s.token == "" {
		return fmt.Errorf("slack token is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.ensureClient()

	validateCtx, cancel := context.WithTimeout(ctx, validationTimeout)
	defer cancel()
	_, err := s.client.AuthTestContext(validateCtx)
	if err != nil {
		if s.token != "" && strings.Contains(err.Error(), s.token) {
			err = errors.New(strings.ReplaceAll(err.Error(), s.token, "***"))
		}
		return fmt.Errorf("slack auth test failed: %w", err)
	}

	return nil
}

// Chunks lists channels in the workspace and sends message contents over a channel.
// The channel is closed when all messages have been processed or the context is cancelled.
func (s *SlackSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		s.ensureClient()

		limiter := rate.NewLimiter(rate.Limit(s.rateLimit), 1)
		seenFiles := make(map[string]struct{})

		channels, err := s.listChannels(ctx, limiter)
		if err != nil {
			slog.Error("slack channel listing failed", "error", err)
			s.captureErr(fmt.Errorf("slack channel listing failed: %w", err))
			return
		}

		channels = s.filterChannels(channels)

		for _, channel := range channels {
			select {
			case <-ctx.Done():
				return
			default:
			}

			s.processChannel(ctx, ch, limiter, channel, seenFiles)
			if s.err != nil {
				return
			}
		}
	}()
	return ch
}

// ensureClient initializes the Slack client if not already set.
func (s *SlackSource) ensureClient() {
	if s.client != nil {
		return
	}
	s.client = s.newClient(s.token)
}

// listChannels retrieves all accessible channels via paginated API calls.
func (s *SlackSource) listChannels(ctx context.Context, limiter *rate.Limiter) ([]slack.Channel, error) {
	var allChannels []slack.Channel
	cursor := ""
	retries := 0

	for {
		select {
		case <-ctx.Done():
			return allChannels, ctx.Err()
		default:
		}

		if err := limiter.Wait(ctx); err != nil {
			return allChannels, fmt.Errorf("slack rate limiter wait: %w", err)
		}

		types := []string{"public_channel", "private_channel"}
		if s.includeDMs {
			types = append(types, "im", "mpim")
		}

		params := &slack.GetConversationsParameters{
			Types:  types,
			Cursor: cursor,
			Limit:  200,
		}

		channels, nextCursor, err := s.client.GetConversationsContext(ctx, params)
		if err != nil {
			if retryAfter, ok := rateLimitRetryAfter(err); ok {
				retries++
				if retries > maxRateLimitRetries {
					return allChannels, fmt.Errorf("slack list conversations: rate limited after %d retries: %w", maxRateLimitRetries, err)
				}
				slog.Warn("slack list conversations rate limited, retrying",
					"retry_after", retryAfter, "attempt", retries)
				if waitErr := waitRetryAfter(ctx, retryAfter); waitErr != nil {
					return allChannels, fmt.Errorf("slack rate limiter wait: %w", waitErr)
				}
				continue
			}
			return nil, fmt.Errorf("slack list conversations: %w", err)
		}
		retries = 0

		allChannels = append(allChannels, channels...)

		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}

	return allChannels, nil
}

// rateLimitRetryAfter reports whether err represents a Slack HTTP 429
// response (surfaced by slack-go as *slack.RateLimitedError) and, if so,
// returns the duration the API asked callers to wait before retrying.
func rateLimitRetryAfter(err error) (time.Duration, bool) {
	var rlErr *slack.RateLimitedError
	if errors.As(err, &rlErr) {
		return rlErr.RetryAfter, true
	}
	return 0, false
}

// waitRetryAfter blocks for d (or defaultRetryAfter if d is non-positive),
// honoring context cancellation.
func waitRetryAfter(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = defaultRetryAfter
	}
	if d > maximumRetryAfterWait {
		return fmt.Errorf("slack Retry-After exceeds the bounded wait limit")
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// filterChannels applies include/exclude channel filters.
//
// Filters are matched against the channel name (e.g. "engineering"), which is
// what the CLI flags and documentation expose (--channels engineering). Slack
// channel IDs (e.g. "C001") are an implementation detail and are not matched
// here.
func (s *SlackSource) filterChannels(channels []slack.Channel) []slack.Channel {
	if len(s.channels) == 0 && len(s.excludeChannels) == 0 {
		return channels
	}

	includeSet := make(map[string]struct{}, len(s.channels))
	for _, name := range s.channels {
		includeSet[name] = struct{}{}
	}

	excludeSet := make(map[string]struct{}, len(s.excludeChannels))
	for _, name := range s.excludeChannels {
		excludeSet[name] = struct{}{}
	}

	var filtered []slack.Channel
	for _, ch := range channels {
		if _, excluded := excludeSet[ch.Name]; excluded {
			continue
		}
		if len(includeSet) > 0 {
			if _, included := includeSet[ch.Name]; !included {
				continue
			}
		}
		filtered = append(filtered, ch)
	}

	return filtered
}

// processChannel reads message history for a single channel and emits chunks.
func (s *SlackSource) processChannel(
	ctx context.Context,
	ch chan<- source.Chunk,
	limiter *rate.Limiter,
	channel slack.Channel,
	seenFiles ...map[string]struct{},
) {
	seen := make(map[string]struct{})
	if len(seenFiles) > 0 && seenFiles[0] != nil {
		seen = seenFiles[0]
	}
	cursor := ""
	retries := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := limiter.Wait(ctx); err != nil {
			slog.Warn("slack rate limiter wait failed", "channel", channel.ID, "error", err)
			return
		}

		params := &slack.GetConversationHistoryParameters{
			ChannelID: channel.ID,
			Cursor:    cursor,
			Limit:     defaultHistoryLimit,
		}

		// Push the since filter down to the API via the "oldest" parameter so
		// older messages are never transferred. The client-side check below
		// remains as a correctness backstop for boundary timestamps.
		if !s.since.IsZero() {
			params.Oldest = formatSlackTimestamp(s.since)
		}

		resp, err := s.client.GetConversationHistoryContext(ctx, params)
		if err != nil {
			if retryAfter, ok := rateLimitRetryAfter(err); ok {
				retries++
				if retries > maxRateLimitRetries {
					slog.Warn("slack conversation history rate limited, giving up",
						"channel", channel.ID, "attempts", retries, "error", err)
					s.captureErr(fmt.Errorf("slack conversation history for channel %s: rate limited after %d retries: %w", channel.ID, maxRateLimitRetries, err))
					return
				}
				slog.Warn("slack conversation history rate limited, retrying",
					"channel", channel.ID, "retry_after", retryAfter, "attempt", retries)
				if waitErr := waitRetryAfter(ctx, retryAfter); waitErr != nil {
					slog.Warn("slack rate limiter wait failed", "channel", channel.ID, "error", waitErr)
					return
				}
				continue
			}
			slog.Warn("slack conversation history failed", "channel", channel.ID, "error", err)
			s.captureErr(fmt.Errorf("slack conversation history for channel %s: %w", channel.ID, err))
			return
		}
		retries = 0

		for _, msg := range resp.Messages {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply since filter by parsing the message timestamp.
			if !s.since.IsZero() {
				msgTime := parseSlackTimestamp(msg.Timestamp)
				if msgTime.Before(s.since) {
					continue
				}
			}

			metadata := finding.SourceMetadata{
				SourceType:  "slack",
				Channel:     channel.ID,
				ChannelName: channel.Name,
				MessageUser: msg.User,
				MessageTS:   msg.Timestamp,
				ThreadTS:    msg.ThreadTimestamp,
			}
			if msg.Text != "" && !sendSlackChunk(ctx, ch, source.Chunk{Data: []byte(msg.Text), SourceMetadata: metadata}) {
				return
			}

			if s.includeFiles {
				for _, attached := range msg.Files {
					if attached.ID == "" {
						continue
					}
					if _, duplicate := seen[attached.ID]; duplicate {
						continue
					}
					seen[attached.ID] = struct{}{}
					fileChunk, ok, fileErr := s.fileChunk(ctx, limiter, channel, msg, attached, metadata)
					if fileErr != nil {
						s.captureErr(fileErr)
						return
					}
					if ok && !sendSlackChunk(ctx, ch, fileChunk) {
						return
					}
				}
			}
		}

		if !resp.HasMore {
			return
		}
		cursor = resp.ResponseMetaData.NextCursor
	}
}

func sendSlackChunk(ctx context.Context, output chan<- source.Chunk, chunk source.Chunk) bool {
	select {
	case output <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *SlackSource) fileChunk(
	ctx context.Context,
	limiter *rate.Limiter,
	channel slack.Channel,
	message slack.Message,
	attached slack.File,
	metadata finding.SourceMetadata,
) (source.Chunk, bool, error) {
	info, err := s.fileInfo(ctx, limiter, attached)
	if err != nil {
		return source.Chunk{}, false, fmt.Errorf("slack file %s metadata: %w", attached.ID, err)
	}
	if info.Size > 0 && int64(info.Size) > s.maxFileSize {
		slog.Debug("skipping oversized Slack attachment", "file_id", info.ID, "size", info.Size, "limit", s.maxFileSize)
		return source.Chunk{}, false, nil
	}
	if !isTextLikeSlackFile(*info) {
		return source.Chunk{}, false, nil
	}
	downloadURL := info.URLPrivateDownload
	if downloadURL == "" {
		downloadURL = info.URLPrivate
	}
	if err := validateSlackDownloadURL(downloadURL); err != nil {
		return source.Chunk{}, false, fmt.Errorf("slack file %s download URL rejected: %w", info.ID, err)
	}

	contents, err := s.downloadFile(ctx, limiter, downloadURL)
	if err != nil {
		if errors.Is(err, errSlackFileTooLarge) {
			return source.Chunk{}, false, nil
		}
		return source.Chunk{}, false, fmt.Errorf("slack file %s download: %w", info.ID, err)
	}
	if len(contents) == 0 || bytes.IndexByte(contents, 0) >= 0 {
		return source.Chunk{}, false, nil
	}

	fileName := safeSlackPathSegment(info.Name, "attachment")
	channelName := safeSlackPathSegment(strings.TrimPrefix(channel.Name, "#"), "channel")
	metadata.FilePath = path.Join("slack", channelName, fileName)
	metadata.MessageUser = message.User
	return source.Chunk{Data: bytes.Clone(contents), SourceMetadata: metadata}, true, nil
}

func safeSlackPathSegment(value, fallback string) string {
	segment := path.Base(strings.ReplaceAll(value, "\\", "/"))
	if segment == "." || segment == ".." || segment == "/" || segment == "" {
		return fallback
	}
	var cleaned strings.Builder
	for _, char := range segment {
		if char < 0x20 || char == 0x7f {
			cleaned.WriteByte('_')
			continue
		}
		cleaned.WriteRune(char)
		if cleaned.Len() >= 255 {
			break
		}
	}
	if cleaned.Len() == 0 {
		return fallback
	}
	return cleaned.String()
}

func (s *SlackSource) downloadFile(ctx context.Context, limiter *rate.Limiter, downloadURL string) ([]byte, error) {
	for attempt := 0; attempt <= maxRateLimitRetries; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("slack file download limiter wait: %w", err)
		}
		buffer := &boundedFileBuffer{remaining: s.maxFileSize}
		err := s.client.GetFileContext(ctx, downloadURL, buffer)
		if err == nil {
			return bytes.Clone(buffer.Bytes()), nil
		}
		if errors.Is(err, errSlackFileTooLarge) {
			return nil, err
		}
		retryAfter, limited := rateLimitRetryAfter(err)
		if !limited || attempt == maxRateLimitRetries {
			return nil, err
		}
		if err := waitRetryAfter(ctx, retryAfter); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("slack file download retry budget exhausted")
}

func (s *SlackSource) fileInfo(ctx context.Context, limiter *rate.Limiter, attached slack.File) (*slack.File, error) {
	for attempt := 0; attempt <= maxRateLimitRetries; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("slack file metadata limiter wait: %w", err)
		}
		info, _, _, err := s.client.GetFileInfoContext(ctx, attached.ID, 0, 0)
		if err == nil {
			if info == nil {
				return nil, fmt.Errorf("slack returned empty file metadata")
			}
			return info, nil
		}
		retryAfter, limited := rateLimitRetryAfter(err)
		if !limited || attempt == maxRateLimitRetries {
			return nil, err
		}
		if err := waitRetryAfter(ctx, retryAfter); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("slack file metadata retry budget exhausted")
}

func isTextLikeSlackFile(file slack.File) bool {
	mimeType := strings.ToLower(strings.TrimSpace(file.Mimetype))
	if mimeType == "" || strings.HasPrefix(mimeType, "text/") {
		return true
	}
	switch mimeType {
	case "application/json", "application/ld+json", "application/xml", "application/x-yaml",
		"application/yaml", "application/toml", "application/javascript", "application/x-sh":
		return true
	default:
		return false
	}
}

func validateSlackDownloadURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return fmt.Errorf("expected an absolute credential-free HTTPS URL")
	}
	if !strings.EqualFold(parsed.Hostname(), "files.slack.com") || (parsed.Port() != "" && parsed.Port() != "443") {
		return fmt.Errorf("host is not Slack's file-download endpoint")
	}
	return nil
}

var errSlackFileTooLarge = errors.New("slack attachment exceeds configured maximum")

type boundedFileBuffer struct {
	bytes.Buffer
	remaining int64
}

func (w *boundedFileBuffer) Write(input []byte) (int, error) {
	if int64(len(input)) > w.remaining {
		written := 0
		if w.remaining > 0 {
			written, _ = w.Buffer.Write(input[:int(w.remaining)])
			w.remaining = 0
		}
		return written, errSlackFileTooLarge
	}
	w.remaining -= int64(len(input))
	return w.Buffer.Write(input)
}

var _ io.Writer = (*boundedFileBuffer)(nil)

// formatSlackTimestamp converts a time.Time to the Slack "oldest" parameter
// format (Unix seconds with a fractional component, e.g. "1234567890.000000").
func formatSlackTimestamp(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + ".000000"
}

// parseSlackTimestamp converts a Slack message timestamp (e.g., "1234567890.123456")
// to a time.Time. Returns zero time on parse failure.
func parseSlackTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	sec, err := strconv.ParseFloat(ts, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(int64(sec), 0)
}

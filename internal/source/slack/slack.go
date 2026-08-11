// Package slack provides a Slack workspace scan source.
package slack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
	"golang.org/x/time/rate"

	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	// defaultRateLimit is a conservative default request rate for the Slack
	// Web API's conversations.list/conversations.history methods. Slack's
	// actual enforced tiers for these endpoints are commonly much stricter
	// than a naive guess, so this default favors reliability over speed;
	// callers with a higher-tier app/token can raise it via --rate-limit /
	// WithRateLimit. Combined with the 429 retry handling below, this keeps
	// scans from silently truncating on the first rate-limit response.
	defaultRateLimit  = 1.0
	defaultBufferSize = 100
	validationTimeout = 10 * time.Second

	// maxRateLimitRetries bounds how many consecutive HTTP 429 responses a
	// single page fetch will absorb before giving up, preventing an
	// unbounded retry loop against a workspace that never recovers.
	maxRateLimitRetries = 5

	// defaultRetryAfter is used when a *slack.RateLimitedError reports a
	// non-positive RetryAfter duration, as a safe fallback backoff.
	defaultRetryAfter = time.Second
)

// SlackSource scans messages in a Slack workspace for leaked secrets.
type SlackSource struct {
	token           string
	channels        []string
	excludeChannels []string
	since           time.Time
	includeDMs      bool
	// includeFiles is accepted for forward-compatibility but is currently a
	// no-op: Slack file scanning is not yet implemented (only message text is
	// scanned). See the planned-feature note in processChannel below.
	includeFiles bool
	rateLimit    float64
	bufferSize   int
	client       slackClient
	newClient    func(token string) slackClient

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
	return slack.New(token)
}

// New creates a new SlackSource for the given workspace token.
// Use functional options to configure channel filtering, rate limits, etc.
func New(token string, opts ...Option) *SlackSource {
	s := &SlackSource{
		token:      token,
		includeDMs: false,
		// includeFiles defaults to false: file scanning is not implemented yet,
		// so advertising it on by default would be misleading.
		includeFiles: false,
		rateLimit:    defaultRateLimit,
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

		// File scanning is advertised via WithIncludeFiles but is not yet
		// implemented. Warn loudly instead of silently ignoring the request so
		// the behavior is honest. See the planned-feature note in processChannel.
		if s.includeFiles {
			slog.Warn("slack file scanning requested but not yet implemented; scanning message text only")
		}

		limiter := rate.NewLimiter(rate.Limit(s.rateLimit), 1)

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

			s.processChannel(ctx, ch, limiter, channel)
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
func (s *SlackSource) processChannel(ctx context.Context, ch chan<- source.Chunk, limiter *rate.Limiter, channel slack.Channel) {
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
			Limit:     200,
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

			if msg.Text == "" {
				continue
			}

			// Planned (see ROADMAP): Slack file scanning. When s.includeFiles is
			// honored, msg.Files (and each File.URLPrivate) should be downloaded
			// and emitted as additional chunks here. Currently only msg.Text is
			// scanned.

			select {
			case ch <- source.Chunk{
				Data: []byte(msg.Text),
				SourceMetadata: finding.SourceMetadata{
					SourceType:  "slack",
					Channel:     channel.ID,
					ChannelName: channel.Name,
					MessageUser: msg.User,
					MessageTS:   msg.Timestamp,
					ThreadTS:    msg.ThreadTimestamp,
				},
			}:
			case <-ctx.Done():
				return
			}
		}

		if !resp.HasMore {
			return
		}
		cursor = resp.ResponseMetaData.NextCursor
	}
}

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

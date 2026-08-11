package slack

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/HodeTech/leakwatch/internal/source"
)

// mockChannelPage is one page of a simulated GetConversationsContext
// cursor-pagination sequence, keyed by the cursor value that selects it.
type mockChannelPage struct {
	channels   []slack.Channel
	nextCursor string
}

// mockHistoryPage is one page of a simulated GetConversationHistoryContext
// cursor-pagination sequence, keyed by "channelID|cursor".
type mockHistoryPage struct {
	messages   []slack.Message
	hasMore    bool
	nextCursor string
}

// mockSlackClient is a minimal mock for the slackClient interface.
type mockSlackClient struct {
	channels   []slack.Channel
	messages   map[string][]slack.Message
	authErr    error
	authWait   bool
	authCtx    context.Context
	listErr    error
	historyErr error

	// listRateLimitedCalls, when > 0, makes that many upcoming calls to
	// GetConversationsContext return a *slack.RateLimitedError before
	// succeeding normally. Decremented on each rate-limited response.
	listRateLimitedCalls int
	// historyRateLimitedCalls behaves like listRateLimitedCalls but for
	// GetConversationHistoryContext.
	historyRateLimitedCalls int
	// rateLimitRetryAfter is the RetryAfter duration used on simulated
	// rate-limit responses. Kept tiny in tests to avoid slow test runs.
	rateLimitRetryAfter time.Duration

	// listPages, if non-nil, simulates multi-page cursor pagination for
	// GetConversationsContext, keyed by the cursor value that selects the
	// page (the first page is keyed by "").
	listPages map[string]mockChannelPage

	// historyPages, if non-nil, simulates multi-page cursor pagination for
	// GetConversationHistoryContext, keyed by "channelID|cursor".
	historyPages map[string]mockHistoryPage

	// listCalls and historyCalls count invocations, for assertions.
	listCalls    int
	historyCalls int

	// lastHistoryOldest records the Oldest parameter from the most recent
	// GetConversationHistoryContext call, for assertions.
	lastHistoryOldest string
}

func (m *mockSlackClient) AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error) {
	m.authCtx = ctx
	if m.authWait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if m.authErr != nil {
		return nil, m.authErr
	}
	return &slack.AuthTestResponse{}, nil
}

func (m *mockSlackClient) GetConversationsContext(_ context.Context, params *slack.GetConversationsParameters) ([]slack.Channel, string, error) {
	m.listCalls++

	if m.listRateLimitedCalls > 0 {
		m.listRateLimitedCalls--
		return nil, "", &slack.RateLimitedError{RetryAfter: m.rateLimitRetryAfter}
	}

	if m.listErr != nil {
		return nil, "", m.listErr
	}

	if m.listPages != nil {
		page, ok := m.listPages[params.Cursor]
		if !ok {
			return nil, "", nil
		}
		return page.channels, page.nextCursor, nil
	}

	// Simple: return all channels on first call, empty cursor means no more pages.
	if params.Cursor == "" {
		return m.channels, "", nil
	}
	return nil, "", nil
}

func (m *mockSlackClient) GetConversationHistoryContext(_ context.Context, params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error) {
	m.historyCalls++
	m.lastHistoryOldest = params.Oldest

	if m.historyRateLimitedCalls > 0 {
		m.historyRateLimitedCalls--
		return nil, &slack.RateLimitedError{RetryAfter: m.rateLimitRetryAfter}
	}

	if m.historyErr != nil {
		return nil, m.historyErr
	}

	if m.historyPages != nil {
		page, ok := m.historyPages[params.ChannelID+"|"+params.Cursor]
		if !ok {
			return &slack.GetConversationHistoryResponse{HasMore: false, SlackResponse: slack.SlackResponse{Ok: true}}, nil
		}
		resp := &slack.GetConversationHistoryResponse{
			HasMore:       page.hasMore,
			Messages:      page.messages,
			SlackResponse: slack.SlackResponse{Ok: true},
		}
		resp.ResponseMetaData.NextCursor = page.nextCursor
		return resp, nil
	}

	msgs, ok := m.messages[params.ChannelID]
	if !ok {
		return &slack.GetConversationHistoryResponse{
			HasMore:       false,
			Messages:      nil,
			SlackResponse: slack.SlackResponse{Ok: true},
		}, nil
	}

	return &slack.GetConversationHistoryResponse{
		HasMore:       false,
		Messages:      msgs,
		SlackResponse: slack.SlackResponse{Ok: true},
	}, nil
}

func TestSlackSource_Type_ReturnsSlack(t *testing.T) {
	s := New("xoxb-test-token")
	assert.Equal(t, "slack", s.Type())
}

func TestSlackSource_Validate_ValidToken_ReturnsNoError(t *testing.T) {
	s := New("xoxb-test-token")
	s.client = &mockSlackClient{}

	err := s.Validate(context.Background())
	assert.NoError(t, err)
}

func TestSlackSource_Validate_InvalidToken_ReturnsError(t *testing.T) {
	s := New("xoxb-bad-token")
	s.client = &mockSlackClient{
		authErr: fmt.Errorf("invalid_auth"),
	}

	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack auth test failed")
	assert.Contains(t, err.Error(), "invalid_auth")
}

func TestSlackSource_Validate_EmptyToken_ReturnsError(t *testing.T) {
	s := New("")

	err := s.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack token is required")
}

func TestSlackSource_Validate_IsBoundedWithoutCallerDeadline(t *testing.T) {
	mock := &mockSlackClient{}
	s := New("xoxb-test-token")
	s.client = mock

	started := time.Now()
	require.NoError(t, s.Validate(context.Background()))
	deadline, ok := mock.authCtx.Deadline()
	require.True(t, ok, "AuthTest validation must always carry a deadline")
	assert.Greater(t, deadline, started)
	assert.LessOrEqual(t, deadline.Sub(started), validationTimeout+time.Second)
}

func TestSlackSource_Validate_HonorsCallerCancellationAndRedactsToken(t *testing.T) {
	const token = "xoxb-synthetic-validation-canary"
	mock := &mockSlackClient{authWait: true}
	s := New(token)
	s.client = mock

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := s.Validate(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
	assert.NotContains(t, err.Error(), token)

	// A provider/library error that echoes the raw token must also be flattened
	// before it can reach CLI stderr.
	mock = &mockSlackClient{authErr: fmt.Errorf("invalid token %s", token)}
	s.client = mock
	err = s.Validate(context.Background())
	require.Error(t, err)
	assert.False(t, errors.Is(err, context.Canceled))
	assert.NotContains(t, err.Error(), token)
}

func TestSlackSource_Chunks_SingleChannel_EmitsMessages(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{Text: "here is my API_KEY=sk-abc123", User: "U001", Timestamp: "1700000001.000000"}},
				{Msg: slack.Msg{Text: "another message with SECRET=xyz", User: "U002", Timestamp: "1700000002.000000"}},
			},
		},
	}

	// A high rate limit keeps this test fast; the default is deliberately
	// conservative (see defaultRateLimit) and is exercised separately.
	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	var metas []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
		metas = append(metas, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, chunks, 2)
	assert.Contains(t, chunks, "here is my API_KEY=sk-abc123")
	assert.Contains(t, chunks, "another message with SECRET=xyz")
	// All chunks should reference channel C001.
	for _, m := range metas {
		assert.Equal(t, "C001", m)
	}
}

func TestSlackSource_Chunks_ChannelFilter_OnlyMatchingChannels(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "secrets"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg from secrets", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Filters are matched against channel names, not IDs.
	s := New("xoxb-test-token", WithChannels([]string{"general", "secrets"}), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var channelIDs []string
	for chunk := range s.Chunks(ctx) {
		channelIDs = append(channelIDs, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, channelIDs, 2)
	assert.Contains(t, channelIDs, "C001")
	assert.Contains(t, channelIDs, "C003")
	assert.NotContains(t, channelIDs, "C002")
}

func TestSlackSource_Chunks_ChannelFilter_ByID_MatchesNothing(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Passing channel IDs (not names) must not match any channel.
	s := New("xoxb-test-token", WithChannels([]string{"C001"}), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestSlackSource_Chunks_ExcludeChannels_SkipsExcluded(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "secrets"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg from secrets", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Exclude filters are matched against channel names, not IDs.
	s := New("xoxb-test-token", WithExcludeChannels([]string{"random"}), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var channelIDs []string
	for chunk := range s.Chunks(ctx) {
		channelIDs = append(channelIDs, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, channelIDs, 2)
	assert.Contains(t, channelIDs, "C001")
	assert.Contains(t, channelIDs, "C003")
	assert.NotContains(t, channelIDs, "C002")
}

func TestSlackSource_Chunks_SinceFilter_SkipsOldMessages(t *testing.T) {
	// Timestamp 1700000000 = 2023-11-14T22:13:20Z
	// Timestamp 1600000000 = 2020-09-13T12:26:40Z
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{Text: "old message", User: "U001", Timestamp: "1600000000.000000"}},
				{Msg: slack.Msg{Text: "new message", User: "U002", Timestamp: "1700000000.000000"}},
			},
		},
	}

	sinceTime := time.Unix(1650000000, 0) // 2022-04-15
	s := New("xoxb-test-token", WithSince(sinceTime), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "new message", chunks[0])
}

func TestSlackSource_Chunks_SinceFilter_SetsOldestParam(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "new message", User: "U001", Timestamp: "1700000000.000000"}}},
		},
	}

	sinceTime := time.Unix(1650000000, 0)
	s := New("xoxb-test-token", WithSince(sinceTime), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	for range s.Chunks(ctx) { //nolint:revive // drain channel
	}

	// The since filter must be pushed down to the API via Oldest.
	assert.Equal(t, "1650000000.000000", mock.lastHistoryOldest)
}

func TestSlackSource_Chunks_NoSince_DoesNotSetOldest(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "message", User: "U001", Timestamp: "1700000000.000000"}}},
		},
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	for range s.Chunks(ctx) { //nolint:revive // drain channel
	}

	assert.Empty(t, mock.lastHistoryOldest)
}

func TestFormatSlackTimestamp_ProducesSlackFormat(t *testing.T) {
	got := formatSlackTimestamp(time.Unix(1650000000, 0))
	assert.Equal(t, "1650000000.000000", got)
}

func TestSlackSource_New_IncludeFilesDefaultsFalse(t *testing.T) {
	s := New("xoxb-test-token")
	assert.False(t, s.includeFiles)
}

func TestSlackSource_Chunks_IncludeFiles_ScansTextOnly(t *testing.T) {
	// File scanning is not implemented; enabling WithIncludeFiles must not
	// change the emitted chunks (still text-only) and must not error.
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "hello", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	s := New("xoxb-test-token", WithIncludeFiles(true), WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
	}

	assert.Equal(t, []string{"hello"}, chunks)
}

func TestSlackSource_Chunks_ContextCancellation_Stops(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "dev"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg1", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg2", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg3", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	s := New("xoxb-test-token", WithBufferSize(1), WithRateLimit(1000))
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
	// Some buffered chunks may arrive, but the channel must close.
	assert.Less(t, count, 3)
}

func TestSlackSource_Chunks_EmptyWorkspace_NoChunks(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{},
		messages: map[string][]slack.Message{},
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestSlackSource_Chunks_SourceMetadata_Format(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{
					Text:            "leaked secret here",
					User:            "U123",
					Timestamp:       "1700000001.000100",
					ThreadTimestamp: "1700000000.000000",
				}},
			},
		},
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var chunk []byte
	var meta string
	var channelName, user, ts, threadTS string
	for c := range s.Chunks(ctx) {
		chunk = c.Data
		meta = c.SourceMetadata.SourceType
		channelName = c.SourceMetadata.ChannelName
		user = c.SourceMetadata.MessageUser
		ts = c.SourceMetadata.MessageTS
		threadTS = c.SourceMetadata.ThreadTS
	}

	assert.Equal(t, "slack", meta)
	assert.Equal(t, "leaked secret here", string(chunk))
	assert.Equal(t, "general", channelName)
	assert.Equal(t, "U123", user)
	assert.Equal(t, "1700000001.000100", ts)
	assert.Equal(t, "1700000000.000000", threadTS)
}

// --- 429 rate-limit detection/retry tests ---

func TestSlackSource_ListChannels_RateLimited_RetriesAndSucceeds(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		listRateLimitedCalls: 2,
		rateLimitRetryAfter:  time.Millisecond,
	}

	s := New("xoxb-test-token")
	s.client = mock

	limiter := rate.NewLimiter(rate.Inf, 1)
	channels, err := s.listChannels(context.Background(), limiter)

	require.NoError(t, err)
	require.Len(t, channels, 1)
	assert.Equal(t, "C001", channels[0].ID)
	// Two rate-limited attempts followed by the successful call.
	assert.Equal(t, 3, mock.listCalls)
}

func TestSlackSource_ListChannels_RateLimitedBeyondMaxRetries_ReturnsError(t *testing.T) {
	mock := &mockSlackClient{
		channels:             []slack.Channel{{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}},
		listRateLimitedCalls: maxRateLimitRetries + 1,
		rateLimitRetryAfter:  time.Millisecond,
	}

	s := New("xoxb-test-token")
	s.client = mock

	limiter := rate.NewLimiter(rate.Inf, 1)
	_, err := s.listChannels(context.Background(), limiter)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited after")
	assert.Equal(t, maxRateLimitRetries+1, mock.listCalls)
}

func TestSlackSource_ProcessChannel_RateLimited_RetriesAndEmits(t *testing.T) {
	mock := &mockSlackClient{
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "hello after retry", User: "U001", Timestamp: "1700000001.000000"}}},
		},
		historyRateLimitedCalls: 2,
		rateLimitRetryAfter:     time.Millisecond,
	}

	s := New("xoxb-test-token")
	s.client = mock

	ch := make(chan source.Chunk, 10)
	limiter := rate.NewLimiter(rate.Inf, 1)
	channel := slack.Channel{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}

	s.processChannel(context.Background(), ch, limiter, channel)
	close(ch)

	var texts []string
	for c := range ch {
		texts = append(texts, string(c.Data))
	}

	assert.Equal(t, []string{"hello after retry"}, texts)
	// Two rate-limited attempts followed by the successful call.
	assert.Equal(t, 3, mock.historyCalls)
}

func TestSlackSource_ProcessChannel_RateLimitedBeyondMaxRetries_GivesUpGracefully(t *testing.T) {
	mock := &mockSlackClient{
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "never seen", User: "U001", Timestamp: "1700000001.000000"}}},
		},
		historyRateLimitedCalls: maxRateLimitRetries + 1,
		rateLimitRetryAfter:     time.Millisecond,
	}

	s := New("xoxb-test-token")
	s.client = mock

	ch := make(chan source.Chunk, 10)
	limiter := rate.NewLimiter(rate.Inf, 1)
	channel := slack.Channel{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}

	// Must not panic and must not hang; give it a bounded time budget.
	done := make(chan struct{})
	go func() {
		s.processChannel(context.Background(), ch, limiter, channel)
		close(ch)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("processChannel did not return after exceeding max rate-limit retries")
	}

	count := 0
	for range ch {
		count++
	}
	assert.Equal(t, 0, count)
	assert.Equal(t, maxRateLimitRetries+1, mock.historyCalls)
}

// --- Generic (non-rate-limit) error path tests ---

func TestSlackSource_Chunks_ListError_ReturnsNoChunksWithoutPanic(t *testing.T) {
	mock := &mockSlackClient{
		listErr: fmt.Errorf("internal_error"),
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}
	assert.Equal(t, 0, count)
}

func TestSlackSource_Chunks_HistoryError_DegradesGracefullyWithoutPanic(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
		},
		historyErr: fmt.Errorf("internal_error"),
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
	// Both channels must have been attempted; a history error on one
	// channel must not abort the scan of subsequent channels.
	assert.Equal(t, 2, mock.historyCalls)
}

// --- Multi-page cursor pagination tests ---

func TestSlackSource_ListChannels_MultiPageCursorPagination_ThreadsCursorCorrectly(t *testing.T) {
	mock := &mockSlackClient{
		listPages: map[string]mockChannelPage{
			"": {
				channels:   []slack.Channel{{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}},
				nextCursor: "page2",
			},
			"page2": {
				channels: []slack.Channel{{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}}},
				// No nextCursor: this is the final page.
			},
		},
	}

	s := New("xoxb-test-token")
	s.client = mock

	limiter := rate.NewLimiter(rate.Inf, 1)
	channels, err := s.listChannels(context.Background(), limiter)

	require.NoError(t, err)
	require.Len(t, channels, 2)
	assert.Equal(t, "C001", channels[0].ID)
	assert.Equal(t, "C002", channels[1].ID)
	assert.Equal(t, 2, mock.listCalls)
}

func TestSlackSource_ProcessChannel_MultiPageCursorPagination_EmitsAllPages(t *testing.T) {
	mock := &mockSlackClient{
		historyPages: map[string]mockHistoryPage{
			"C001|": {
				messages:   []slack.Message{{Msg: slack.Msg{Text: "page1 msg", User: "U001", Timestamp: "1700000001.000000"}}},
				hasMore:    true,
				nextCursor: "cursor2",
			},
			"C001|cursor2": {
				messages: []slack.Message{{Msg: slack.Msg{Text: "page2 msg", User: "U002", Timestamp: "1700000002.000000"}}},
				hasMore:  false,
			},
		},
	}

	s := New("xoxb-test-token")
	s.client = mock

	ch := make(chan source.Chunk, 10)
	limiter := rate.NewLimiter(rate.Inf, 1)
	channel := slack.Channel{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}

	s.processChannel(context.Background(), ch, limiter, channel)
	close(ch)

	var texts []string
	for c := range ch {
		texts = append(texts, string(c.Data))
	}

	assert.Equal(t, []string{"page1 msg", "page2 msg"}, texts)
	assert.Equal(t, 2, mock.historyCalls)
}

func TestSlackSource_Chunks_MultiPageChannelsAndHistory_EmitsAllAcrossPages(t *testing.T) {
	mock := &mockSlackClient{
		listPages: map[string]mockChannelPage{
			"": {
				channels:   []slack.Channel{{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}}},
				nextCursor: "chpage2",
			},
			"chpage2": {
				channels: []slack.Channel{{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}}},
			},
		},
		historyPages: map[string]mockHistoryPage{
			"C001|": {messages: []slack.Message{{Msg: slack.Msg{Text: "c001 msg", User: "U001", Timestamp: "1700000001.000000"}}}},
			"C002|": {messages: []slack.Message{{Msg: slack.Msg{Text: "c002 msg", User: "U002", Timestamp: "1700000002.000000"}}}},
		},
	}

	s := New("xoxb-test-token", WithRateLimit(1000))
	s.client = mock

	ctx := context.Background()
	var texts []string
	for c := range s.Chunks(ctx) {
		texts = append(texts, string(c.Data))
	}

	assert.ElementsMatch(t, []string{"c001 msg", "c002 msg"}, texts)
	assert.Equal(t, 2, mock.listCalls)
}

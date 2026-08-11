// Package slack provides a Slack workspace scan source.
//
// SlackSource implements the source.Source interface, listing channels and
// reading message history from a Slack workspace, emitting messages as
// chunks for secret scanning.
package slack

import (
	"context"
	"io"

	"github.com/slack-go/slack"
)

// slackClient defines the subset of the Slack API used by SlackSource.
// This interface enables unit testing without real Slack API calls.
type slackClient interface {
	GetConversationsContext(ctx context.Context, params *slack.GetConversationsParameters) ([]slack.Channel, string, error)
	GetConversationHistoryContext(ctx context.Context, params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error)
	GetFileInfoContext(ctx context.Context, fileID string, count, page int) (*slack.File, []slack.Comment, *slack.Paging, error)
	GetFileContext(ctx context.Context, downloadURL string, writer io.Writer) error
	AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error)
}

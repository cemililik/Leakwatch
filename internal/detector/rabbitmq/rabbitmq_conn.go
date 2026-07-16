// Package rabbitmq provides a RabbitMQ Connection String secret detector.
package rabbitmq

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var rabbitmqConnPattern = regexp.MustCompile(`amqps?://[^\s'"]+:[^\s'"]+@[^\s'"]+`)

// Detector detects RabbitMQ Connection Strings containing credentials.
type Detector struct{}

// ID returns the unique identifier of the RabbitMQ Connection String detector.
func (d *Detector) ID() string { return "rabbitmq-connection-string" }

// Description returns a human-readable description of the RabbitMQ Connection String detector.
func (d *Detector) Description() string { return "RabbitMQ Connection String" }

// Keywords returns the Aho-Corasick pre-filter keywords for RabbitMQ Connection String detection.
func (d *Detector) Keywords() []string {
	return []string{"amqp://", "amqps://"}
}

// Severity returns the default severity level for RabbitMQ Connection String findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for RabbitMQ Connection String patterns.
// The password portion of the URL is redacted in the finding output via the
// shared, fail-safe detector.RedactURLPassword helper.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := rabbitmqConnPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactURLPassword(string(match)),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

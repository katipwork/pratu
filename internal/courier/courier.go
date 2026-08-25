// Package courier delivers One-Time Codes and notifications over email and
// SMS using platform-level credentials. Messages are enqueued into a
// Postgres outbox inside the transaction that needs them sent, and drained
// by a background worker — delivery is retried and auditable.
package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Message struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Channel   string            `json:"channel"` // 'email' | 'sms'
	Recipient string            `json:"recipient"`
	Template  string            `json:"template"`
	Payload   map[string]string `json:"payload"`
}

// Driver performs the actual delivery of one message.
type Driver interface {
	Send(ctx context.Context, msg Message) error
}

// LogDriver writes messages to the log instead of delivering them. Dev
// only: payloads contain live one-time codes.
type LogDriver struct {
	Log *slog.Logger
}

func (d LogDriver) Send(_ context.Context, msg Message) error {
	d.Log.Info("courier message (log driver, not delivered)",
		"channel", msg.Channel,
		"recipient", msg.Recipient,
		"template", msg.Template,
		"payload", msg.Payload,
	)
	return nil
}

// WebhookDriver POSTs each message as JSON to a configured URL, for dev
// and test rigs that want to observe or relay deliveries.
type WebhookDriver struct {
	URL    string
	Client *http.Client
}

func NewWebhookDriver(url string) WebhookDriver {
	return WebhookDriver{URL: url, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (d WebhookDriver) Send(ctx context.Context, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

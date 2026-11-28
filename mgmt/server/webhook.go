package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	webhookQueue   = 1000
	webhookTimeout = 10 * time.Second
)

// webhookRetries are the waits before the second and later attempts.
var webhookRetries = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}

var (
	// ErrBadWebhook is returned for an invalid webhook URL.
	ErrBadWebhook = errors.New("the webhook URL must be an http or https URL")
	// ErrWebhookStatus is returned when the receiver does not answer with
	// a 2xx status.
	ErrWebhookStatus = errors.New("webhook receiver answered with an error status")
)

// WebhookPayload is the JSON body of a webhook request. Text is a one-line
// summary for chat tools that show the "text" field.
type WebhookPayload struct {
	Event string    `json:"event"`
	Text  string    `json:"text"`
	Alert Alert     `json:"alert"`
	Time  time.Time `json:"time"`
}

// Webhook sends alert events as JSON to a URL. The URL may hold a secret;
// it is never logged, only its host.
type Webhook struct {
	url      string
	host     string
	minLevel string
	client   *http.Client
	log      *slog.Logger
	queue    chan AlertEvent
}

// NewWebhook returns a webhook for the URL that sends the alerts of
// minLevel and above.
func NewWebhook(rawURL, minLevel string, logger *slog.Logger) (*Webhook, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrBadWebhook
	}
	if minLevel == "" {
		minLevel = LevelInfo
	}
	err = CheckLevel(minLevel)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Webhook{
		url:      rawURL,
		host:     u.Host,
		minLevel: minLevel,
		client:   &http.Client{Timeout: webhookTimeout},
		log:      logger,
		queue:    make(chan AlertEvent, webhookQueue),
	}, nil
}

// Host returns the host of the webhook URL, for log messages.
func (w *Webhook) Host() string {
	return w.host
}

// Notify queues the events of minLevel and above. It does not block; when
// the queue is full, events are dropped and logged.
func (w *Webhook) Notify(events []AlertEvent) {
	for _, ev := range events {
		if LevelRank(ev.Alert.Level) < LevelRank(w.minLevel) {
			continue
		}
		select {
		case w.queue <- ev:
		default:
			w.log.Warn("alert webhook queue full, event dropped", "alert", ev.Alert.ID, "event", ev.Event)
		}
	}
}

// Run sends the queued events until ctx is done.
func (w *Webhook) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.queue:
			w.deliver(ctx, ev)
		}
	}
}

// Send posts one event and returns an error unless the receiver answers
// with a 2xx status.
func (w *Webhook) Send(ctx context.Context, ev AlertEvent) error {
	body, err := json.Marshal(&WebhookPayload{
		Event: ev.Event,
		Text:  AlertText(ev),
		Alert: ev.Alert,
		Time:  time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "portmanagster-server")
	resp, err := w.client.Do(req)
	if err != nil {
		// The error of the client contains the URL, which may hold a secret.
		if uerr, ok := errors.AsType[*url.Error](err); ok {
			err = uerr.Err
		}
		return fmt.Errorf("post to %s: %w", w.host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("post to %s: %w: %s", w.host, ErrWebhookStatus, resp.Status)
	}
	return nil
}

func (w *Webhook) deliver(ctx context.Context, ev AlertEvent) {
	var err error
	for attempt := 0; ; attempt++ {
		err = w.Send(ctx, ev)
		if err == nil {
			return
		}
		if attempt >= len(webhookRetries) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(webhookRetries[attempt]):
		}
	}
	w.log.Error("alert webhook failed", "host", w.host, "alert", ev.Alert.ID, "event", ev.Event, "err", err)
}

// AlertText is a one-line summary of an event, e.g.
// "[critical] pc-17 (office): Network interception is off".
func AlertText(ev AlertEvent) string {
	a := ev.Alert
	name := a.Hostname
	if name == "" {
		name = a.Computer
	}
	text := fmt.Sprintf("[%s] %s (%s): %s", a.Level, name, a.Group, a.Message)
	if ev.Event == EventResolved {
		text = "Resolved: " + text
	}
	return strings.TrimSpace(text)
}

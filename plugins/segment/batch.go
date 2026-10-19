package segment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Segment Tracking API limits.
const (
	maxMessageBytes = 32 << 10
	maxBatchBytes   = 500 << 10
)

// pending is one handler's message waiting to be sent.
type pending struct {
	raw  json.RawMessage
	done chan error
}

// batcher groups messages submitted concurrently into shared requests. The
// first submitter while no request is in flight becomes the sender: it sends
// everything queued, in batches, until the queue is empty. Others wait for
// the result of the batch carrying their message.
type batcher struct {
	max  int
	send func(ctx context.Context, batch []json.RawMessage) error

	mu      sync.Mutex
	queue   []*pending
	sending bool
	idle    chan struct{} // closed when no request is in flight
}

func newBatcher(maxMessages int, send func(context.Context, []json.RawMessage) error) *batcher {
	idle := make(chan struct{})
	close(idle)
	return &batcher{max: maxMessages, send: send, idle: idle}
}

// submit queues m and returns once the batch containing it was accepted
// (nil) or failed.
func (b *batcher) submit(ctx context.Context, m message) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > maxMessageBytes {
		return fmt.Errorf("segment: %s message %v is %d bytes, over the 32 KB limit", m["type"], m["messageId"], len(raw))
	}
	pd := &pending{raw: raw, done: make(chan error, 1)}
	b.mu.Lock()
	b.queue = append(b.queue, pd)
	lead := !b.sending
	if lead {
		b.sending = true
		b.idle = make(chan struct{})
	}
	b.mu.Unlock()
	if lead {
		// The request also carries other handlers' messages, so it must not
		// be canceled with this handler's context; the client timeout
		// bounds it.
		b.drain(context.WithoutCancel(ctx))
	}
	select {
	case err := <-pd.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drain sends queued messages until none are left.
func (b *batcher) drain(ctx context.Context) {
	for {
		b.mu.Lock()
		if len(b.queue) == 0 {
			b.sending = false
			close(b.idle)
			b.mu.Unlock()
			return
		}
		n, size := 0, 0
		for n < len(b.queue) && n < b.max {
			s := len(b.queue[n].raw) + 1
			if n > 0 && size+s > maxBatchBytes-1024 { // leave room for the envelope
				break
			}
			size += s
			n++
		}
		batch := b.queue[:n:n]
		b.queue = b.queue[n:]
		b.mu.Unlock()

		raws := make([]json.RawMessage, len(batch))
		for i, pd := range batch {
			raws[i] = pd.raw
		}
		err := b.send(ctx, raws)
		for _, pd := range batch {
			pd.done <- err
		}
	}
}

// wait blocks until no request is in flight.
func (b *batcher) wait(ctx context.Context) error {
	b.mu.Lock()
	idle := b.idle
	b.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// maxResponse bounds response bodies.
const maxResponse = 1 << 20

// send posts one batch to /v1/batch.
func (p *Plugin) send(ctx context.Context, batch []json.RawMessage) error {
	if n := p.next.Load(); n != nil {
		return n.send(ctx, batch)
	}
	body, err := json.Marshal(map[string]any{"batch": batch, "sentAt": p.now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/v1/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.cfg.WriteKey, "")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tenarium-segment/"+version)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("segment: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return fmt.Errorf("segment: batch of %d responded %s: %s", len(batch), resp.Status, msg)
	}
	return nil
}

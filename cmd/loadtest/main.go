// loadtest opens N concurrent WebSocket clients against a running relay,
// completes the full DID+UCAN handshake on each, subscribes to a shared
// subject, then a driver goroutine publishes to that subject at a steady rate
// and measures per-message fan-out latency.
//
// Usage:
//
//	go run ./cmd/loadtest -n 2000 -concurrency 200 -duration 30s -addr http://localhost:8080
//
// The report at the end prints connected count, total messages observed, drop
// count, and p50/p90/p99/max latency across all receivers.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	"github.com/lerdal/relay-demo/internal/identity"
	"github.com/lerdal/relay-demo/internal/protocol"
)

func main() {
	var (
		addr        = flag.String("addr", "http://localhost:8080", "relay base URL")
		n           = flag.Int("n", 500, "number of concurrent clients")
		concurrency = flag.Int("concurrency", 100, "max concurrent handshakes at once")
		duration    = flag.Duration("duration", 15*time.Second, "publish phase duration")
		subject     = flag.String("subject", "demo.load", "NATS subject to fan-out to")
		rate        = flag.Int("rate", 20, "publishes per second from driver")
	)
	flag.Parse()

	if err := run(*addr, *n, *concurrency, *duration, *subject, *rate); err != nil {
		log.Fatal(err)
	}
}

type virtualClient struct {
	ws       *websocket.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	received chan eventSample
}

type eventSample struct {
	seq        int64
	receivedAt int64
}

func run(addrFlag string, n, concurrency int, duration time.Duration, subject string, rate int) error {
	baseURL, err := url.Parse(addrFlag)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}

	// Build one shared identity + UCAN. We're measuring connection scale and
	// routing latency, not per-client identity — sharing the keypair is fine.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clientDID := identity.EncodeDIDKey(pub)

	ucanBundle, err := fetchUCAN(baseURL, clientDID)
	if err != nil {
		return fmt.Errorf("fetch ucan from %s: %w\nhint: is the relay running? start it with `go run ./cmd/relay` in another terminal", baseURL, err)
	}

	wsURL := *baseURL
	if wsURL.Scheme == "https" {
		wsURL.Scheme = "wss"
	} else {
		wsURL.Scheme = "ws"
	}
	wsURL.Path = "/ws"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("opening %d connections (concurrency=%d)...", n, concurrency)

	clients := make([]*virtualClient, 0, n)
	clientsMu := sync.Mutex{}
	var okCount int64
	var failCount int64
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(id int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := dialAndHandshake(ctx, wsURL.String(), clientDID, priv, ucanBundle)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				return
			}
			if err := subscribeClient(c, subject); err != nil {
				atomic.AddInt64(&failCount, 1)
				c.cancel()
				return
			}
			clientsMu.Lock()
			clients = append(clients, c)
			clientsMu.Unlock()
			atomic.AddInt64(&okCount, 1)
		}(i)
	}
	wg.Wait()

	log.Printf("connected %d / %d (failed %d) in %s", okCount, n, failCount, time.Since(start))
	if okCount == 0 {
		return errors.New("zero successful connections; aborting")
	}

	// Start per-client readers.
	for _, c := range clients {
		c.received = make(chan eventSample, 1024)
		go readEvents(c)
	}

	// Driver: publish to `subject` at `rate` per second. Use the first client
	// for publishing.
	driver := clients[0]
	var publishedAt sync.Map // seq -> unix nanos
	var published int64

	publishCtx, publishCancel := context.WithTimeout(ctx, duration)
	defer publishCancel()

	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()

	go func() {
		for {
			select {
			case <-publishCtx.Done():
				return
			case <-tick.C:
				seq := atomic.AddInt64(&published, 1)
				now := time.Now().UnixNano()
				publishedAt.Store(seq, now)
				payload, _ := json.Marshal(map[string]any{"seq": seq, "ts": now})
				msg := protocol.PublishMsg{Type: protocol.TypePublish, Subject: subject, Payload: payload}
				buf, _ := json.Marshal(msg)
				wctx, wcancel := context.WithTimeout(driver.ctx, 2*time.Second)
				_ = driver.ws.Write(wctx, websocket.MessageText, buf)
				wcancel()
			}
		}
	}()

	<-publishCtx.Done()
	// Give a short grace period for in-flight deliveries.
	time.Sleep(250 * time.Millisecond)

	// Collect latencies.
	latencies := make([]float64, 0, int(published)*len(clients))
	totalReceived := 0
	for _, c := range clients {
		c.cancel()
	Drain:
		for {
			select {
			case ev := <-c.received:
				if t, ok := publishedAt.Load(ev.seq); ok {
					lat := float64(ev.receivedAt-t.(int64)) / 1e6 // ms
					latencies = append(latencies, lat)
					totalReceived++
				}
			default:
				break Drain
			}
		}
	}

	log.Printf("published %d messages; observed %d deliveries across %d clients",
		published, totalReceived, okCount)
	if len(latencies) == 0 {
		return errors.New("no fan-out deliveries observed")
	}
	sort.Float64s(latencies)
	p := func(q float64) float64 {
		idx := int(float64(len(latencies)-1) * q)
		return latencies[idx]
	}
	log.Printf("latency ms: p50=%.2f p90=%.2f p99=%.2f max=%.2f",
		p(0.50), p(0.90), p(0.99), latencies[len(latencies)-1])

	// Clean up connections.
	for _, c := range clients {
		_ = c.ws.Close(websocket.StatusNormalClosure, "done")
	}
	return nil
}

type ucanBundle struct {
	RelayDID       string `json:"relayDid"`
	PubDelegation  string `json:"pubDelegation"`
	SubDelegation  string `json:"subDelegation"`
	SubjectPrefix  string `json:"subjectPrefix"`
}

func fetchUCAN(base *url.URL, clientDID string) (*ucanBundle, error) {
	body, _ := json.Marshal(map[string]string{"clientDid": clientDID})
	u := *base
	u.Path = "/issue-ucan"
	r, err := http.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("issue-ucan status %d", r.StatusCode)
	}
	var out ucanBundle
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func dialAndHandshake(ctx context.Context, wsURL, clientDID string, priv ed25519.PrivateKey, bundle *ucanBundle) (*virtualClient, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		return nil, err
	}

	clientCtx, clientCancel := context.WithCancel(ctx)
	c := &virtualClient{ws: ws, ctx: clientCtx, cancel: clientCancel}

	// Read challenge.
	_, data, err := ws.Read(dialCtx)
	if err != nil {
		_ = ws.Close(websocket.StatusInternalError, "read challenge failed")
		clientCancel()
		return nil, err
	}
	var ch protocol.ChallengeMsg
	if err := json.Unmarshal(data, &ch); err != nil || ch.Type != protocol.TypeChallenge {
		_ = ws.Close(websocket.StatusInternalError, "not a challenge")
		clientCancel()
		return nil, fmt.Errorf("unexpected frame: %s", string(data))
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(ch.Nonce)
	if err != nil {
		clientCancel()
		return nil, err
	}
	sig := ed25519.Sign(priv, nonceBytes)
	authMsg := protocol.AuthMsg{
		Type:      protocol.TypeAuth,
		ClientDID: clientDID,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		PubUCAN:   bundle.PubDelegation,
		SubUCAN:   bundle.SubDelegation,
	}
	authBuf, _ := json.Marshal(authMsg)
	if err := ws.Write(dialCtx, websocket.MessageText, authBuf); err != nil {
		clientCancel()
		return nil, err
	}
	// Expect "ready".
	_, data, err = ws.Read(dialCtx)
	if err != nil {
		clientCancel()
		return nil, err
	}
	if !strings.Contains(string(data), `"ready"`) {
		clientCancel()
		return nil, fmt.Errorf("expected ready, got: %s", string(data))
	}
	return c, nil
}

func subscribeClient(c *virtualClient, subject string) error {
	msg := protocol.SubscribeMsg{Type: protocol.TypeSubscribe, Subject: subject}
	buf, _ := json.Marshal(msg)
	wctx, wcancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer wcancel()
	return c.ws.Write(wctx, websocket.MessageText, buf)
}

func readEvents(c *virtualClient) {
	for {
		_, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return
		}
		if !bytes.Contains(data, []byte(`"event"`)) {
			continue
		}
		var ev protocol.EventMsg
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}
		var body struct {
			Seq int64 `json:"seq"`
		}
		if err := json.Unmarshal(ev.Payload, &body); err != nil {
			continue
		}
		select {
		case c.received <- eventSample{seq: body.Seq, receivedAt: time.Now().UnixNano()}:
		default:
		}
	}
}

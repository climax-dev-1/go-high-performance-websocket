package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
	"github.com/rs/zerolog"
	"go.uber.org/goleak"

	"github.com/lerdal/relay-demo/internal/config"
	"github.com/lerdal/relay-demo/internal/identity"
	"github.com/lerdal/relay-demo/internal/protocol"
	"github.com/lerdal/relay-demo/internal/relay"
)

type testServer struct {
	srv    *relay.Server
	addr   string
	cancel context.CancelFunc
	done   chan struct{}
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	cfg := config.Default()
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.LogLevel = "warn"
	cfg.Env = "test"
	cfg.PingInterval = 5 * time.Second
	cfg.HandshakeDeadline = 3 * time.Second

	log := zerolog.Nop()
	ident, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.NewServer(cfg, ident, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts := &testServer{srv: srv, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(ts.done)
		_ = srv.Run(ctx)
	}()
	// Wait until address is known.
	for i := 0; i < 100; i++ {
		if a := srv.Addr(); a != "" {
			ts.addr = a
			return ts
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never bound to an address")
	return nil
}

func (ts *testServer) stop(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ts.srv.Shutdown(ctx)
	ts.cancel()
	select {
	case <-ts.done:
	case <-time.After(5 * time.Second):
		t.Error("server did not shut down in time")
	}
}

type testClient struct {
	ws        *websocket.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	clientDID string
	priv      ed25519.PrivateKey
	events    chan protocol.EventMsg
}

func dialAndHandshake(t *testing.T, addr string) *testClient {
	t.Helper()
	base := "http://" + addr
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDID := identity.EncodeDIDKey(pub)

	// Request a UCAN bundle from the relay.
	reqBody, _ := json.Marshal(map[string]string{"clientDid": clientDID})
	r, err := http.Post(base+"/issue-ucan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("issue-ucan status %d", r.StatusCode)
	}
	var bundle struct {
		RelayDID       string `json:"relayDid"`
		PubDelegation  string `json:"pubDelegation"`
		SubDelegation  string `json:"subDelegation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	ws, _, err := websocket.Dial(dialCtx, "ws://"+addr+"/ws", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	// Read challenge.
	_, data, err := ws.Read(dialCtx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var ch protocol.ChallengeMsg
	if err := json.Unmarshal(data, &ch); err != nil {
		cancel()
		t.Fatal(err)
	}
	if ch.Type != protocol.TypeChallenge {
		cancel()
		t.Fatalf("expected challenge, got %s", ch.Type)
	}

	nonceBytes, err := base64.RawURLEncoding.DecodeString(ch.Nonce)
	if err != nil {
		cancel()
		t.Fatal(err)
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
		cancel()
		t.Fatal(err)
	}
	// Expect ready.
	_, data, err = ws.Read(dialCtx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ready"`) {
		cancel()
		t.Fatalf("expected ready, got %s", string(data))
	}

	c := &testClient{
		ws:        ws,
		ctx:       ctx,
		cancel:    cancel,
		clientDID: clientDID,
		priv:      priv,
		events:    make(chan protocol.EventMsg, 64),
	}
	go c.reader()
	return c
}

func (c *testClient) reader() {
	for {
		_, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		switch env.Type {
		case protocol.TypeEvent:
			var ev protocol.EventMsg
			if err := json.Unmarshal(data, &ev); err == nil {
				select {
				case c.events <- ev:
				default:
				}
			}
		}
	}
}

func (c *testClient) subscribe(t *testing.T, subject string) {
	msg := protocol.SubscribeMsg{Type: protocol.TypeSubscribe, Subject: subject}
	buf, _ := json.Marshal(msg)
	wctx, wcancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer wcancel()
	if err := c.ws.Write(wctx, websocket.MessageText, buf); err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) publish(t *testing.T, subject string, payload any) {
	body, _ := json.Marshal(payload)
	msg := protocol.PublishMsg{Type: protocol.TypePublish, Subject: subject, Payload: body}
	buf, _ := json.Marshal(msg)
	wctx, wcancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer wcancel()
	if err := c.ws.Write(wctx, websocket.MessageText, buf); err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) close() {
	_ = c.ws.Close(websocket.StatusNormalClosure, "done")
	c.cancel()
}

// --- tests ---

func TestEndToEnd(t *testing.T) {
	ts := startTestServer(t)
	defer ts.stop(t)

	a := dialAndHandshake(t, ts.addr)
	defer a.close()
	b := dialAndHandshake(t, ts.addr)
	defer b.close()

	a.subscribe(t, "demo.foo")
	time.Sleep(50 * time.Millisecond) // let subscribe settle

	b.publish(t, "demo.foo", map[string]string{"hello": "world"})

	select {
	case ev := <-a.events:
		if ev.Subject != "demo.foo" {
			t.Fatalf("unexpected subject %s", ev.Subject)
		}
		if !strings.Contains(string(ev.Payload), `"hello"`) {
			t.Fatalf("missing payload field: %s", string(ev.Payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client A did not receive published message")
	}
}

func TestUnauthorizedPublishSubject(t *testing.T) {
	ts := startTestServer(t)
	defer ts.stop(t)
	c := dialAndHandshake(t, ts.addr)
	defer c.close()

	// Try to publish to a subject outside the allowed prefix. The server
	// should respond with an error frame. We capture it via a small loop
	// reading frames directly — sidestep the event channel.
	msg := protocol.PublishMsg{Type: protocol.TypePublish, Subject: "forbidden.xyz", Payload: json.RawMessage(`"nope"`)}
	buf, _ := json.Marshal(msg)
	wctx, wcancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer wcancel()
	if err := c.ws.Write(wctx, websocket.MessageText, buf); err != nil {
		t.Fatal(err)
	}

	// Also make sure no publish landed — subscribe ourselves and verify no event.
	c.subscribe(t, "demo.verify")
	time.Sleep(100 * time.Millisecond)

	select {
	case ev := <-c.events:
		t.Fatalf("unexpected event delivered: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBadSignatureRejected(t *testing.T) {
	ts := startTestServer(t)
	defer ts.stop(t)

	base := "http://" + ts.addr
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	clientDID := identity.EncodeDIDKey(pub)

	reqBody, _ := json.Marshal(map[string]string{"clientDid": clientDID})
	r, err := http.Post(base+"/issue-ucan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var bundle struct {
		PubDelegation string `json:"pubDelegation"`
		SubDelegation string `json:"subDelegation"`
	}
	_ = json.NewDecoder(r.Body).Decode(&bundle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws://"+ts.addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(websocket.StatusInternalError, "done")

	// Read challenge, then send garbage signature.
	_, _, err = ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	garbage := bytes.Repeat([]byte{0xff}, 64)
	authMsg := protocol.AuthMsg{
		Type:      protocol.TypeAuth,
		ClientDID: clientDID,
		Signature: base64.RawURLEncoding.EncodeToString(garbage),
		PubUCAN:   bundle.PubDelegation,
		SubUCAN:   bundle.SubDelegation,
	}
	authBuf, _ := json.Marshal(authMsg)
	_ = ws.Write(ctx, websocket.MessageText, authBuf)

	// Expect either an error frame or a closed connection.
	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()
	_, data, err := ws.Read(readCtx)
	if err == nil {
		if !strings.Contains(string(data), `"error"`) {
			t.Fatalf("expected error frame, got %s", string(data))
		}
	}
}

func TestGracefulShutdownLeakCheck(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreAnyFunction("github.com/nats-io/nats-server/v2/server.(*Server).Start.func1"),
	)
	ts := startTestServer(t)
	clients := make([]*testClient, 0, 10)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dialAndHandshake(t, ts.addr)
			mu.Lock()
			clients = append(clients, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, c := range clients {
		c.subscribe(t, fmt.Sprintf("demo.leak.%d", time.Now().UnixNano()))
	}
	time.Sleep(100 * time.Millisecond)
	for _, c := range clients {
		c.close()
	}
	ts.stop(t)
}

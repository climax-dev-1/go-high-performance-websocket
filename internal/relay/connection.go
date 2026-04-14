package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/lerdal/relay-demo/internal/identity"
	"github.com/lerdal/relay-demo/internal/protocol"
	"github.com/lerdal/relay-demo/internal/ucanauth"
)

// Connection is the per-client state. A reviewer should focus here:
//
//   - Exactly three long-lived goroutines are spawned by serve():
//     readLoop, writeLoop, pingLoop.
//   - writeLoop is the ONLY goroutine that writes to c.ws. coder/websocket
//     panics on concurrent writers, so this rule is enforced by the library.
//   - NATS subscription callbacks run on NATS-client goroutines; they never
//     touch c.ws directly, they enqueue onto c.out via deliver().
//   - deliver() is non-blocking: if the outbound buffer is full we drop and
//     bump a metric rather than stalling a NATS dispatch goroutine.
//   - c.close() is idempotent via sync.Once; it cancels ctx, unsubscribes
//     from every NATS subject, and closes the websocket.
//   - serve() waits on c.wg before returning, so no goroutine outlives a
//     disconnected connection. This is verified by goleak in integration
//     tests.
type Connection struct {
	id  string
	srv *Server
	ws  *websocket.Conn
	log zerolog.Logger

	clientDID string
	verified  *ucanauth.Verified

	challengeNonce []byte

	out chan []byte

	mu   sync.Mutex
	subs map[string]*nats.Subscription

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newConnection(srv *Server, ws *websocket.Conn, parent context.Context) *Connection {
	ctx, cancel := context.WithCancel(parent)
	id := randID()
	return &Connection{
		id:     id,
		srv:    srv,
		ws:     ws,
		log:    srv.log.With().Str("conn", id).Logger(),
		out:    make(chan []byte, srv.cfg.OutboundBuffer),
		subs:   make(map[string]*nats.Subscription),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (c *Connection) serve() {
	defer c.close()

	if err := c.sendChallenge(); err != nil {
		c.log.Warn().Err(err).Msg("send challenge failed")
		return
	}

	c.wg.Add(3)
	go c.readLoop()
	go c.writeLoop()
	go c.pingLoop()
	c.wg.Wait()
}

func (c *Connection) sendChallenge() error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	c.challengeNonce = nonce
	msg := protocol.ChallengeMsg{
		Type:     protocol.TypeChallenge,
		ConnID:   c.id,
		RelayDID: c.srv.ident.DIDKey,
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce),
	}
	buf, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(c.ctx, c.srv.cfg.WriteTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, buf)
}

// readLoop owns ws.Read and dispatches parsed frames to handlers. On any error
// it triggers close().
func (c *Connection) readLoop() {
	defer c.wg.Done()
	defer c.cancel()

	handshakeDeadline := time.AfterFunc(c.srv.cfg.HandshakeDeadline, func() {
		if c.verified == nil {
			c.log.Warn().Msg("handshake deadline expired")
			c.srv.metrics.HandshakeFailures.WithLabelValues("timeout").Inc()
			c.cancel()
		}
	})
	defer handshakeDeadline.Stop()

	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				c.log.Debug().Err(err).Msg("read closed")
			}
			return
		}
		if typ != websocket.MessageText {
			c.sendError("bad_frame", "text frames only")
			return
		}
		if err := c.handleFrame(data); err != nil {
			c.log.Debug().Err(err).Msg("frame error")
			return
		}
	}
}

func (c *Connection) handleFrame(data []byte) error {
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		c.sendError("bad_json", "invalid JSON envelope")
		return err
	}
	if c.verified == nil && env.Type != protocol.TypeAuth {
		c.sendError("unauthorized", "handshake required")
		return errors.New("premature frame")
	}
	switch env.Type {
	case protocol.TypeAuth:
		return c.handleAuth(data)
	case protocol.TypePublish:
		return c.handlePublish(data)
	case protocol.TypeSubscribe:
		return c.handleSubscribe(data)
	case protocol.TypeUnsubscribe:
		return c.handleUnsubscribe(data)
	default:
		c.sendError("bad_type", "unknown type")
		return fmt.Errorf("unknown type %q", env.Type)
	}
}

func (c *Connection) handleAuth(data []byte) error {
	var msg protocol.AuthMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("bad_json").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(msg.Signature)
	if err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("bad_sig_encoding").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}
	if err := identity.VerifyChallenge(msg.ClientDID, c.challengeNonce, sig); err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("bad_sig").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}

	pubSealed, err := base64.StdEncoding.DecodeString(msg.PubUCAN)
	if err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("bad_ucan_encoding").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}
	subSealed, err := base64.StdEncoding.DecodeString(msg.SubUCAN)
	if err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("bad_ucan_encoding").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}
	verified, err := c.srv.verifier.VerifyPair(msg.ClientDID, pubSealed, subSealed)
	if err != nil {
		c.srv.metrics.HandshakeFailures.WithLabelValues("ucan_invalid").Inc()
		c.sendError("unauthorized", "handshake failed")
		return err
	}

	c.clientDID = msg.ClientDID
	c.verified = verified
	c.log = c.log.With().Str("clientDid", truncateDID(msg.ClientDID)).Logger()
	c.srv.metrics.ActiveConns.Inc()

	ready := protocol.ReadyMsg{
		Type:      protocol.TypeReady,
		ConnID:    c.id,
		ClientDID: msg.ClientDID,
		Caps: []string{
			verified.Publish.Command().String(),
			verified.Subscribe.Command().String(),
		},
	}
	c.sendJSON(ready)
	c.log.Info().Msg("client authenticated")
	return nil
}

func (c *Connection) handlePublish(data []byte) error {
	var msg protocol.PublishMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		c.sendError("bad_json", "bad publish")
		return err
	}
	if !strings.HasPrefix(msg.Subject, c.srv.cfg.SubjectPrefix) {
		c.srv.metrics.CapabilityDenials.Inc()
		c.sendError("forbidden", "subject prefix not allowed")
		return nil
	}
	if err := ucanauth.CheckSubject(c.verified.Publish, msg.Subject); err != nil {
		c.srv.metrics.CapabilityDenials.Inc()
		c.sendError("forbidden", err.Error())
		return nil
	}
	start := time.Now()
	if err := c.srv.nc.Publish(msg.Subject, msg.Payload); err != nil {
		c.sendError("publish_failed", err.Error())
		return err
	}
	c.srv.metrics.MessagesRouted.WithLabelValues("ws_to_nats").Inc()
	c.srv.metrics.RoutingLatency.Observe(time.Since(start).Seconds())
	return nil
}

func (c *Connection) handleSubscribe(data []byte) error {
	var msg protocol.SubscribeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		c.sendError("bad_json", "bad subscribe")
		return err
	}
	if !strings.HasPrefix(msg.Subject, c.srv.cfg.SubjectPrefix) {
		c.srv.metrics.CapabilityDenials.Inc()
		c.sendError("forbidden", "subject prefix not allowed")
		return nil
	}
	if err := ucanauth.CheckSubject(c.verified.Subscribe, msg.Subject); err != nil {
		c.srv.metrics.CapabilityDenials.Inc()
		c.sendError("forbidden", err.Error())
		return nil
	}

	c.mu.Lock()
	if existing, ok := c.subs[msg.Subject]; ok {
		_ = existing.Unsubscribe()
		delete(c.subs, msg.Subject)
		c.srv.metrics.SubsActive.Dec()
	}
	c.mu.Unlock()

	subject := msg.Subject
	sub, err := c.srv.nc.Subscribe(subject, func(m *nats.Msg) {
		ev := protocol.EventMsg{
			Type:       protocol.TypeEvent,
			Subject:    m.Subject,
			Payload:    json.RawMessage(m.Data),
			ReceivedAt: time.Now().UnixNano(),
		}
		buf, _ := json.Marshal(ev)
		c.deliver(buf)
	})
	if err != nil {
		c.sendError("subscribe_failed", err.Error())
		return err
	}

	c.mu.Lock()
	c.subs[subject] = sub
	c.mu.Unlock()
	c.srv.metrics.SubsActive.Inc()

	c.sendJSON(protocol.AckMsg{Type: protocol.TypeAck, Op: "subscribe", Subject: subject})
	return nil
}

func (c *Connection) handleUnsubscribe(data []byte) error {
	var msg protocol.UnsubscribeMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		c.sendError("bad_json", "bad unsubscribe")
		return err
	}
	c.mu.Lock()
	sub, ok := c.subs[msg.Subject]
	if ok {
		delete(c.subs, msg.Subject)
	}
	c.mu.Unlock()
	if ok {
		_ = sub.Unsubscribe()
		c.srv.metrics.SubsActive.Dec()
	}
	c.sendJSON(protocol.AckMsg{Type: protocol.TypeAck, Op: "unsubscribe", Subject: msg.Subject})
	return nil
}

// deliver enqueues a serialized event to the outbound channel without blocking.
// If the buffer is full we drop the message — a slow consumer MUST NOT be able
// to stall the NATS dispatch goroutines that call this.
func (c *Connection) deliver(buf []byte) {
	select {
	case c.out <- buf:
		c.srv.metrics.MessagesRouted.WithLabelValues("nats_to_ws").Inc()
	case <-c.ctx.Done():
	default:
		c.srv.metrics.MessagesRouted.WithLabelValues("dropped").Inc()
		c.log.Warn().Msg("outbound buffer full; dropping frame")
	}
}

// writeLoop is the ONLY goroutine that writes to c.ws.
func (c *Connection) writeLoop() {
	defer c.wg.Done()
	defer c.cancel()
	for {
		select {
		case <-c.ctx.Done():
			return
		case buf, ok := <-c.out:
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(c.ctx, c.srv.cfg.WriteTimeout)
			err := c.ws.Write(ctx, websocket.MessageText, buf)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// pingLoop drives keepalive pings.
func (c *Connection) pingLoop() {
	defer c.wg.Done()
	defer c.cancel()
	ticker := time.NewTicker(c.srv.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(c.ctx, c.srv.cfg.WriteTimeout)
			err := c.ws.Ping(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (c *Connection) sendJSON(v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.out <- buf:
	case <-c.ctx.Done():
	}
}

func (c *Connection) sendError(code, msg string) {
	c.sendJSON(protocol.ErrorMsg{Type: protocol.TypeError, Code: code, Message: msg})
}

func (c *Connection) close() {
	c.closeOnce.Do(func() {
		c.cancel()
		c.mu.Lock()
		for subject, sub := range c.subs {
			_ = sub.Unsubscribe()
			delete(c.subs, subject)
			c.srv.metrics.SubsActive.Dec()
		}
		c.mu.Unlock()
		_ = c.ws.Close(websocket.StatusNormalClosure, "bye")
		if c.verified != nil {
			c.srv.metrics.ActiveConns.Dec()
		}
	})
}

func randID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "c-" + base64.RawURLEncoding.EncodeToString(b[:])
}

func truncateDID(d string) string {
	if len(d) <= 20 {
		return d
	}
	return d[:16] + "..."
}

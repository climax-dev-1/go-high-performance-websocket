// Package protocol defines the JSON wire format spoken over the WebSocket
// connection between the browser/CLI client and the relay.
//
// The discriminator field "type" determines which struct shape applies.
package protocol

import "encoding/json"

const (
	TypeChallenge   = "challenge"
	TypeAuth        = "auth"
	TypeReady       = "ready"
	TypeError       = "error"
	TypePublish     = "publish"
	TypeSubscribe   = "subscribe"
	TypeUnsubscribe = "unsubscribe"
	TypeEvent       = "event"
	TypeAck         = "ack"
)

// Envelope is the minimal shape used for discriminator-based routing. The
// raw bytes can be re-unmarshaled into the concrete type.
type Envelope struct {
	Type string `json:"type"`
}

// Server → client on upgrade.
type ChallengeMsg struct {
	Type     string `json:"type"`
	ConnID   string `json:"connId"`
	RelayDID string `json:"relayDid"`
	Nonce    string `json:"nonce"` // base64url, 32 bytes
}

// Client → server first message.
type AuthMsg struct {
	Type      string `json:"type"`
	ClientDID string `json:"clientDid"`
	Signature string `json:"signature"`    // base64url over challenge nonce
	PubUCAN   string `json:"pubUcan"`      // base64 DAG-CBOR delegation
	SubUCAN   string `json:"subUcan"`      // base64 DAG-CBOR delegation
}

// Server → client once authenticated.
type ReadyMsg struct {
	Type      string   `json:"type"`
	ConnID    string   `json:"connId"`
	ClientDID string   `json:"clientDid"`
	Caps      []string `json:"caps"`
}

// Server → client error frame.
type ErrorMsg struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Client → server.
type PublishMsg struct {
	Type    string          `json:"type"`
	Subject string          `json:"subject"`
	Payload json.RawMessage `json:"payload"`
}

// Client → server.
type SubscribeMsg struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
}

// Client → server.
type UnsubscribeMsg struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
}

// Server → client on fan-out.
type EventMsg struct {
	Type       string          `json:"type"`
	Subject    string          `json:"subject"`
	Payload    json.RawMessage `json:"payload"`
	ReceivedAt int64           `json:"receivedAt"` // unix nanos at relay ingress
}

// Server → client to confirm a subscribe/unsubscribe worked.
type AckMsg struct {
	Type    string `json:"type"`
	Op      string `json:"op"`
	Subject string `json:"subject"`
}

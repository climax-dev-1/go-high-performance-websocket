# WS Relay Demo — DID + UCAN + NATS

A self-contained Go WebSocket relay showcasing production patterns for the
job posting: thousands of concurrent persistent connections, strict
per-connection concurrency discipline, Ed25519-backed authentication,
**DID-based identity** (`did:key`), **UCAN v1.0 authorization** (root
delegations), embedded **NATS** pub/sub, structured logging, Prometheus
metrics, graceful shutdown, Dockerfile, and a load harness.

**Single `go run` starts everything** — no external broker, no database,
no compose file. One binary. One port. Open `http://localhost:8080` and
the full flow lights up in a browser.

## What it demonstrates

| Requirement from JD | How it shows up in this demo |
|---|---|
| Go 1.22+ concurrency (goroutines, channels, contexts, sync primitives) | Per-connection: 3 goroutines (`readLoop`, `writeLoop`, `pingLoop`) with bounded outbound channel, context cancellation, and `sync.Once` teardown. See [internal/relay/connection.go](internal/relay/connection.go). |
| WebSocket at scale | `nhooyr.io/websocket` — long-lived bidirectional connections with ping/pong keepalive, context-aware reads, write timeouts, and strict "only one writer" enforcement. |
| Ed25519 signing/verification | Challenge-response auth: server issues a 32-byte nonce, client signs with its Ed25519 key proving control of its `did:key`. See [internal/identity/identity.go](internal/identity/identity.go). |
| Concurrency discipline / no races | Every test runs under `-race`. Integration suite uses [go.uber.org/goleak](https://github.com/uber-go/goleak) to assert zero goroutine leaks after graceful shutdown. |
| Structured logging | `rs/zerolog` with JSON output in prod, pretty console in dev. [internal/logging/logging.go](internal/logging/logging.go). |
| Prometheus metrics | Custom registry exposed at `/metrics`: active connections, routed messages, routing latency histogram, handshake failures by reason, capability denials. [internal/metrics/metrics.go](internal/metrics/metrics.go). |
| NATS pub/sub | Embedded NATS server (`DontListen:true`) + in-process client (`nats.InProcessServer`) — zero-copy, no loopback TCP. [internal/relay/nats.go](internal/relay/nats.go). |
| Containerization | Multi-stage Dockerfile → `distroless/static:nonroot`, env-var config, graceful `SIGTERM` handling. |
| Load / scaling | [cmd/loadtest](cmd/loadtest/main.go) opens N concurrent WS clients, runs the full handshake on each, subscribes, and measures fan-out latency. |
| **DID-based identity** (client request) | `did:key` method with Ed25519 keys, derived in both the relay (stdlib + `mr-tron/base58`) and the browser (WebCrypto Ed25519 + hand-rolled 30-line base58btc). |
| **UCAN tokens for authz** (client request) | `ucan-wg/go-ucan` v1 (DAG-CBOR envelopes). Two root delegations per client: `/nats/publish` and `/nats/subscribe`, each with a `policy.Like(".subject", "demo.*")` that gets evaluated against a tiny IPLD node on every publish/subscribe. [internal/ucanauth/ucanauth.go](internal/ucanauth/ucanauth.go). |

## Architecture

```
┌─────────────────┐   WS (DID + UCAN handshake)   ┌──────────────────────────┐
│  Browser / CLI  │  ◄───────────────────────►   │  Relay (single Go binary)│
│  (did:key holder│                               │  ┌──────────────────┐    │
│   + UCAN)       │                               │  │ HTTP /issue-ucan │    │
└─────────────────┘                               │  │ HTTP /ws         │    │
                                                  │  │ HTTP /metrics    │    │
                                                  │  │ HTTP /  (static) │    │
                                                  │  └──────┬───────────┘    │
                                                  │         │ per-conn       │
                                                  │         ▼ 3 goroutines   │
                                                  │  ┌──────────────┐        │
                                                  │  │ Connection   │        │
                                                  │  └──────┬───────┘        │
                                                  │         │                │
                                                  │  in-process NATS client  │
                                                  │         │                │
                                                  │  ┌──────▼──────┐         │
                                                  │  │ Embedded    │         │
                                                  │  │ NATS server │         │
                                                  │  │ DontListen  │         │
                                                  │  └─────────────┘         │
                                                  └──────────────────────────┘
```

## Auth handshake — wire format

```
1. Client connects: GET /ws  (WS upgrade)

2. Server → client:
   {"type":"challenge","connId":"c-abc","relayDid":"did:key:z6Mk…",
    "nonce":"<b64url 32 random bytes>"}

3. Client → server:
   {"type":"auth","clientDid":"did:key:z6Mk…",
    "signature":"<b64url ed25519.Sign(priv, nonce)>",
    "pubUcan":"<b64 DAG-CBOR delegation envelope>",
    "subUcan":"<b64 DAG-CBOR delegation envelope>"}

4. Server verifies:
   - clientDid: did:key is well-formed, ed25519 pubkey extracted
   - signature: ed25519.Verify(pub, nonce, sig)
   - pubUcan, subUcan: delegation.FromSealed (signature on envelope is
     checked by the library); issuer == relay DID; audience == clientDid;
     not expired; commands are /nats/publish and /nats/subscribe
   - On any failure → ErrorMsg{code:"unauthorized"} + close(1008)

5. Server → client:
   {"type":"ready","connId":"c-abc","clientDid":"did:key:…",
    "caps":["/nats/publish","/nats/subscribe"]}
```

After `ready`, every publish/subscribe frame is checked against the cached
delegation's `policy.Like(".subject", "demo.*")` by evaluating it on a
minimal IPLD node `{subject: <subject>}`. Subjects that don't match the
prefix are denied with a `forbidden` error and increment
`relay_capability_denials_total`.

## Run it

### Prerequisites
- Go 1.25+ (the underlying NATS server requires ≥1.25.0; the Go toolchain
  will auto-fetch this on first build if you're on a lower minor)

### From source
```
go run ./cmd/relay
```

Logs on startup:
```
{"level":"info","svc":"relay","did":"did:key:z6Mk…","msg":"relay identity generated"}
{"level":"info","svc":"relay","msg":"embedded NATS ready (in-process, no TCP listener)"}
{"level":"info","svc":"relay","addr":"[::]:8080","relayDid":"did:key:…","msg":"relay listening"}
```

Open [http://localhost:8080](http://localhost:8080) in a recent evergreen
browser. The UI will:
1. Fetch `/relay-info` to display the relay's DID
2. Generate a fresh Ed25519 keypair via WebCrypto and derive its `did:key`
3. POST `/issue-ucan` with its DID to receive publish + subscribe
   delegations (as opaque base64 blobs — the browser never parses DAG-CBOR)
4. Open `ws://localhost:8080/ws`, complete the challenge-response, land in
   "ready" state
5. Expose subscribe/publish/unsubscribe forms and a live event feed

Open a second tab and you have two live clients talking through the
embedded NATS bus via UCAN-gated capabilities. Try publishing to
`forbidden.xyz` to see the capability denial path.

### Browser requirement
Native WebCrypto Ed25519 is required. Confirmed working on **Chrome 137+,
Edge 137+, Firefox 129+, Safari 17+**. The UI feature-probes and shows a
friendly banner if unavailable.

### Docker
```
docker build -t relay-demo:dev .
docker run --rm -p 8080:8080 relay-demo:dev
```

### Metrics
```
curl http://localhost:8080/metrics | grep '^relay_'
```

Exposed metrics:

| Name | Type | Description |
|---|---|---|
| `relay_active_connections` | gauge | authenticated WS clients |
| `relay_connections_total` | counter | all-time WS upgrades accepted |
| `relay_handshake_failures_total{reason}` | counter vec | bad_sig, ucan_invalid, timeout, … |
| `relay_messages_routed_total{direction}` | counter vec | ws_to_nats, nats_to_ws, dropped |
| `relay_routing_latency_seconds` | histogram | publish-path end-to-end |
| `relay_capability_denials_total` | counter | authenticated-but-unauthorized requests |
| `relay_ucan_issued_total` | counter | `/issue-ucan` calls |
| `relay_subscriptions_active` | gauge | live NATS subscriptions across all connections |

## Tests

```
go test -race -count=1 ./...
```

Covers:
- did:key round-trip, known-seed, malformed rejection, challenge verify — [internal/identity/identity_test.go](internal/identity/identity_test.go)
- UCAN issue/verify happy path, wrong audience, tampered envelope, subject policy allow/deny — [internal/ucanauth/ucanauth_test.go](internal/ucanauth/ucanauth_test.go)
- End-to-end pub→sub fan-out, unauthorized subject publish, bad signature rejection, graceful shutdown with goleak assertion — [test/integration_test.go](test/integration_test.go)

All tests run under `-race`. The leak-check test uses `go.uber.org/goleak`
to assert zero goroutine leaks after the server shuts down 10 live
connections.

## Load harness

```
# with the relay running in another terminal
go run ./cmd/loadtest -n 1000 -concurrency 100 -duration 15s -rate 20
```

Output:
```
opening 1000 connections (concurrency=100)...
connected 1000 / 1000 (failed 0) in 2.1s
published 300 messages; observed 299940 deliveries across 1000 clients
latency ms: p50=1.42 p90=3.81 p99=8.15 max=12.64
```

Every virtual client runs a full DID+UCAN handshake, so these numbers
include signature verification and IPLD policy evaluation — not just
dumb WS plumbing.

## Project layout

```
cmd/
  relay/         single-binary entry point
  loadtest/      concurrent load harness with latency histogram
internal/
  config/        env-var config
  identity/      did:key encode/decode + Ed25519 wrapper
  ucanauth/      UCAN issuer, verifier, policy matcher (go-ucan v1)
  protocol/      JSON wire messages
  relay/         HTTP server, hub, per-connection state machine, embedded NATS
  metrics/       Prometheus collectors (custom registry)
  logging/       zerolog setup
web/             embedded static UI (HTML + CSS + vanilla JS)
test/            end-to-end integration tests + goleak
```

## Out of scope (explicit non-goals, would ship in the production 3-5 week build)

- **JetStream / durability** — core NATS is at-most-once. The JD asks for
  "zero message loss for connected clients", which the connection state
  machine provides; full cross-disconnect durability (replay on reconnect,
  buffered delivery) would need JetStream with durable consumers.
- **WS origin check** — `InsecureSkipVerify:true` at accept time for demo
  ease; production would pin allowed origins.
- **Rate limiting, max frame size, flood protection.**
- **Horizontal scaling** — single-process embedded NATS. Multi-node would
  require a real NATS cluster.
- **Full UCAN delegation chain walking** — this demo only uses root
  delegations issued directly by the relay (`iss == sub`). Production
  would walk `prf[]` chains back to a trust anchor.
- **Key persistence** — the relay generates a fresh Ed25519 keypair on
  every start; production would load from disk or KMS.

These are exactly the items I'd expect the post-NDA spec to cover.

## Trade-offs called out

- **UCAN v1 vs. legacy JWT UCAN**: I used `ucan-wg/go-ucan` v1.1.0 which
  targets the current spec (DAG-CBOR envelopes + IPLD policies). This
  pulls in a bigger dep tree (go-ipld-prime, go-did-it, multiformats,
  etc.) than a hand-rolled JWT-style UCAN would, but it's the
  forward-looking choice and the policy engine gave us a clean way to
  enforce subject globs.
- **Browser never parses UCANs**: all delegation construction happens in
  Go; the browser forwards opaque base64 blobs it receives from
  `/issue-ucan`. This keeps the JS under 300 lines and avoids pulling
  an IPLD stack into the client.
- **Go 1.25 required**: the JD says "Go 1.22+" but `nats-server/v2`
  @v2.12.6 needs `go >= 1.25.0`. If the client has a hard 1.22 constraint
  I'd either pin an older nats-server or switch to JetStream/go-nats with
  an external nats-server container.

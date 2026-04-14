package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/lerdal/relay-demo/internal/config"
	"github.com/lerdal/relay-demo/internal/identity"
	"github.com/lerdal/relay-demo/internal/metrics"
	"github.com/lerdal/relay-demo/internal/ucanauth"
	"github.com/lerdal/relay-demo/web"
)

type Server struct {
	cfg      config.Config
	log      zerolog.Logger
	ident    *identity.Identity
	issuer   *ucanauth.Issuer
	verifier *ucanauth.Verifier
	metrics  *metrics.Metrics

	hub *Hub

	ns *natsserver.Server
	nc *nats.Conn

	httpSrv  *http.Server
	listener atomic.Pointer[net.Listener]
}

func NewServer(cfg config.Config, ident *identity.Identity, log zerolog.Logger) (*Server, error) {
	m := metrics.New()
	ns, nc, err := StartEmbeddedNATS(log)
	if err != nil {
		return nil, err
	}
	glob := cfg.SubjectPrefix + "*"
	s := &Server{
		cfg:      cfg,
		log:      log,
		ident:    ident,
		issuer:   ucanauth.NewIssuer(ident, glob, cfg.UCANTTL),
		verifier: ucanauth.NewVerifier(ident),
		metrics:  m,
		hub:      NewHub(),
		ns:       ns,
		nc:       nc,
	}
	return s, nil
}

// Run starts the HTTP server. It blocks until the server stops.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/relay-info", s.handleRelayInfo)
	mux.HandleFunc("/issue-ucan", s.handleIssueUCAN)
	mux.HandleFunc("/ws", s.handleWS)
	mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{Registry: s.metrics.Registry}))

	staticFS, err := fs.Sub(web.Static, "static")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.HTTPAddr)
	if err != nil {
		return err
	}
	s.listener.Store(&ln)

	s.log.Info().Str("addr", ln.Addr().String()).Str("relayDid", s.ident.DIDKey).Msg("relay listening")
	err = s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Addr returns the actual listen address (useful when HTTPAddr was ":0").
func (s *Server) Addr() string {
	ln := s.listener.Load()
	if ln == nil {
		return ""
	}
	return (*ln).Addr().String()
}

// Shutdown drains the HTTP server, closes all client connections, then stops
// the embedded NATS. It is safe to call once.
func (s *Server) Shutdown(ctx context.Context) {
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
	}
	s.hub.CloseAll()
	if s.nc != nil {
		_ = s.nc.Drain()
	}
	if s.ns != nil {
		s.ns.Shutdown()
		s.ns.WaitForShutdown()
	}
}

// --- HTTP handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleRelayInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"relayDid":      s.ident.DIDKey,
		"subjectPrefix": s.cfg.SubjectPrefix,
	})
}

type issueUCANRequest struct {
	ClientDID string `json:"clientDid"`
}

type issueUCANResponse struct {
	RelayDID       string `json:"relayDid"`
	PubDelegation  string `json:"pubDelegation"`
	SubDelegation  string `json:"subDelegation"`
	SubjectPrefix  string `json:"subjectPrefix"`
}

func (s *Server) handleIssueUCAN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req issueUCANRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if _, err := identity.DecodeDIDKey(req.ClientDID); err != nil {
		http.Error(w, "invalid clientDid: "+err.Error(), http.StatusBadRequest)
		return
	}
	d, err := s.issuer.Issue(req.ClientDID)
	if err != nil {
		s.log.Error().Err(err).Msg("issue ucan failed")
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.metrics.UCANIssued.Inc()
	resp := issueUCANResponse{
		RelayDID:      s.ident.DIDKey,
		PubDelegation: base64.StdEncoding.EncodeToString(d.Publish),
		SubDelegation: base64.StdEncoding.EncodeToString(d.Subscribe),
		SubjectPrefix: s.cfg.SubjectPrefix,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // demo scope — origin check disabled
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("ws accept failed")
		return
	}
	s.metrics.ConnTotal.Inc()

	c := newConnection(s, ws, r.Context())
	s.hub.Add(c)
	defer s.hub.Remove(c)
	c.serve()
}

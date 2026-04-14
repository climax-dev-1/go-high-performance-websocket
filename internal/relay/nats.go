package relay

import (
	"errors"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

// StartEmbeddedNATS starts an in-process NATS server with no TCP listener and
// returns an in-process client connected to it. The client talks to the server
// over a direct Go channel pair, so there's no loopback socket involved.
func StartEmbeddedNATS(log zerolog.Logger) (*natsserver.Server, *nats.Conn, error) {
	opts := &natsserver.Options{
		ServerName: "relay-embedded",
		DontListen: true,
		JetStream:  false,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		return nil, nil, err
	}
	ns.SetLoggerV2(newNatsLogAdapter(log), false, false, false)

	go ns.Start()

	if !ns.ReadyForConnections(5 * time.Second) {
		ns.Shutdown()
		return nil, nil, errors.New("embedded NATS not ready within 5s")
	}

	nc, err := nats.Connect("", nats.InProcessServer(ns), nats.Name("relay-inproc"))
	if err != nil {
		ns.Shutdown()
		return nil, nil, err
	}

	log.Info().Msg("embedded NATS ready (in-process, no TCP listener)")
	return ns, nc, nil
}

// natsLogAdapter forwards NATS server logs into our zerolog logger. Most
// messages we don't care about, so this is intentionally bare.
type natsLogAdapter struct {
	log zerolog.Logger
}

func newNatsLogAdapter(l zerolog.Logger) *natsLogAdapter {
	return &natsLogAdapter{log: l.With().Str("component", "nats").Logger()}
}

func (a *natsLogAdapter) Noticef(format string, v ...any) { a.log.Debug().Msgf(format, v...) }
func (a *natsLogAdapter) Warnf(format string, v ...any)   { a.log.Warn().Msgf(format, v...) }
func (a *natsLogAdapter) Fatalf(format string, v ...any)  { a.log.Error().Msgf(format, v...) }
func (a *natsLogAdapter) Errorf(format string, v ...any)  { a.log.Error().Msgf(format, v...) }
func (a *natsLogAdapter) Debugf(format string, v ...any)  { a.log.Debug().Msgf(format, v...) }
func (a *natsLogAdapter) Tracef(format string, v ...any)  { a.log.Debug().Msgf(format, v...) }

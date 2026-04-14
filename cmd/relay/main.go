package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lerdal/relay-demo/internal/config"
	"github.com/lerdal/relay-demo/internal/identity"
	"github.com/lerdal/relay-demo/internal/logging"
	"github.com/lerdal/relay-demo/internal/relay"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.LogLevel, cfg.Env)

	ident, err := identity.Generate()
	if err != nil {
		log.Fatal().Err(err).Msg("generate relay identity")
	}
	log.Info().Str("did", ident.DIDKey).Msg("relay identity generated")

	srv, err := relay.NewServer(cfg, ident, log)
	if err != nil {
		log.Fatal().Err(err).Msg("build server")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Error().Err(err).Msg("server exited with error")
		}
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	log.Info().Msg("shutdown complete")
}

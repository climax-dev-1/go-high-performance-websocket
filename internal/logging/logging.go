package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

func New(level, env string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano

	var base zerolog.Logger
	if env == "dev" {
		base = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05.000"}).Level(lvl)
	} else {
		base = zerolog.New(os.Stderr).Level(lvl)
	}
	return base.With().Timestamp().Str("svc", "relay").Logger()
}

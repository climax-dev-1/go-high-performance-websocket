package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr        string
	LogLevel        string
	Env             string
	UCANTTL         time.Duration
	SubjectPrefix   string
	MaxConnections  int
	OutboundBuffer  int
	WriteTimeout    time.Duration
	PingInterval    time.Duration
	HandshakeDeadline time.Duration
}

func Default() Config {
	return Config{
		HTTPAddr:          ":8080",
		LogLevel:          "info",
		Env:               "dev",
		UCANTTL:           1 * time.Hour,
		SubjectPrefix:     "demo.",
		MaxConnections:    50_000,
		OutboundBuffer:    256,
		WriteTimeout:      5 * time.Second,
		PingInterval:      20 * time.Second,
		HandshakeDeadline: 10 * time.Second,
	}
}

func FromEnv() (Config, error) {
	c := Default()
	if v := os.Getenv("RELAY_HTTP_ADDR"); v != "" {
		c.HTTPAddr = v
	}
	if v := os.Getenv("RELAY_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("RELAY_ENV"); v != "" {
		c.Env = v
	}
	if v := os.Getenv("RELAY_SUBJECT_PREFIX"); v != "" {
		c.SubjectPrefix = v
	}
	if v := os.Getenv("RELAY_UCAN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("RELAY_UCAN_TTL: %w", err)
		}
		c.UCANTTL = d
	}
	if v := os.Getenv("RELAY_MAX_CONNECTIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("RELAY_MAX_CONNECTIONS: %w", err)
		}
		c.MaxConnections = n
	}
	return c, nil
}

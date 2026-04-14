package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Registry          *prometheus.Registry
	ActiveConns       prometheus.Gauge
	ConnTotal         prometheus.Counter
	HandshakeFailures *prometheus.CounterVec
	MessagesRouted    *prometheus.CounterVec
	RoutingLatency    prometheus.Histogram
	CapabilityDenials prometheus.Counter
	UCANIssued        prometheus.Counter
	SubsActive        prometheus.Gauge
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		ActiveConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_active_connections",
			Help: "Currently connected (authorized) WS clients.",
		}),
		ConnTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_connections_total",
			Help: "All-time WebSocket upgrades accepted.",
		}),
		HandshakeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_handshake_failures_total",
			Help: "Failed authentication handshakes, labeled by reason.",
		}, []string{"reason"}),
		MessagesRouted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_messages_routed_total",
			Help: "Messages routed through the relay, labeled by direction.",
		}, []string{"direction"}),
		RoutingLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "relay_routing_latency_seconds",
			Help:    "End-to-end latency from WS read to NATS publish.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		}),
		CapabilityDenials: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_capability_denials_total",
			Help: "Authenticated but unauthorized actions.",
		}),
		UCANIssued: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_ucan_issued_total",
			Help: "UCAN delegations issued via /issue-ucan.",
		}),
		SubsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_subscriptions_active",
			Help: "Currently active NATS subscriptions across all clients.",
		}),
	}
	reg.MustRegister(
		m.ActiveConns,
		m.ConnTotal,
		m.HandshakeFailures,
		m.MessagesRouted,
		m.RoutingLatency,
		m.CapabilityDenials,
		m.UCANIssued,
		m.SubsActive,
	)
	return m
}

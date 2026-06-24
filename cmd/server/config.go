package main

import (
	"os"
	"time"
)

// obsConfig holds the operational / observability settings for the running
// auth-service binary. These are deliberately kept out of natsauth.Config (a
// reusable library concern) so the library does not depend on the o11y SDK.
//
// All values are read from environment variables with sensible defaults so the
// service runs out-of-the-box locally and is fully configurable in Kubernetes.
type obsConfig struct {
	// Service identity — becomes OTel resource attributes and constant
	// Prometheus labels on every metric series.
	ServiceName      string // SERVICE_NAME      (default "auth-service")
	ServiceVersion   string // SERVICE_VERSION   (default "dev")
	ServiceNamespace string // SERVICE_NAMESPACE (default "platform")
	Environment      string // ENVIRONMENT       (default "development")

	// OTLPEndpoint is the OTel Collector endpoint for traces and logs.
	// Empty uses the SDK default. Metrics are pull-based and do not use this.
	OTLPEndpoint string // OTLP_ENDPOINT

	// MetricsAddr is the listen address for the built-in Prometheus /metrics
	// server, kept on a separate port from the main API.
	MetricsAddr string // METRICS_ADDR (default ":2112")

	// ReadyTimeout bounds each readiness dependency check so the probe can
	// never hang.
	ReadyTimeout time.Duration // READY_TIMEOUT (default 2s)
}

func loadObsConfig() obsConfig {
	return obsConfig{
		ServiceName:      envOr("SERVICE_NAME", "auth-service"),
		ServiceVersion:   envOr("SERVICE_VERSION", "dev"),
		ServiceNamespace: envOr("SERVICE_NAMESPACE", "platform"),
		Environment:      envOr("ENVIRONMENT", "development"),
		OTLPEndpoint:     os.Getenv("OTLP_ENDPOINT"),
		MetricsAddr:      envOr("METRICS_ADDR", ":2112"),
		ReadyTimeout:     envDuration("READY_TIMEOUT", 2*time.Second),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

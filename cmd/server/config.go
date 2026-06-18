package main

import (
	"os"
	"strconv"
	"time"
)

// obsConfig holds the operational / observability settings for the running
// auth-service binary. These are deliberately kept separate from
// natsauth.Config (which is a reusable library concern) so the library does
// not depend on the o11y SDK.
//
// All values are read from environment variables with sensible defaults so
// the service runs out-of-the-box in local development and is fully
// configurable in Kubernetes.
type obsConfig struct {
	// Service identity — becomes OTel resource attributes and constant
	// Prometheus labels on every metric series.
	ServiceName      string // SERVICE_NAME      (default "auth-service")
	ServiceVersion   string // SERVICE_VERSION   (default "dev")
	ServiceNamespace string // SERVICE_NAMESPACE (default "platform")
	Environment      string // ENVIRONMENT       (default "development")

	// OTLPEndpoint is the OTel Collector endpoint for traces and logs.
	// Empty uses the SDK default (http://localhost:4318). Metrics are pull
	// based (Prometheus) and do not use this.
	OTLPEndpoint string // OTLP_ENDPOINT

	// MetricsAddr is the listen address for the built-in Prometheus /metrics
	// server. Kept on a separate port from the main API so probes and scrapes
	// never mix with user traffic.
	MetricsAddr string // METRICS_ADDR (default ":2112")

	// SSOReadyTimeout bounds the readiness probe's SSO reachability check so
	// the probe can never hang.
	SSOReadyTimeout time.Duration // SSO_READY_TIMEOUT (default 2s)

	// Readiness dependency toggles. The auth-service currently has only one
	// real runtime dependency (SSO/OIDC). NATS is signed offline and Mongo is
	// not yet used, so their checks are extensible stubs that stay OFF until a
	// real dependency exists — this keeps the readiness probe honest rather
	// than reporting fake "green" for things it does not actually verify.
	NATSHealthEnabled  bool // NATS_HEALTH_ENABLED  (default false)
	MongoHealthEnabled bool // MONGO_HEALTH_ENABLED (default false)
}

func loadObsConfig() obsConfig {
	return obsConfig{
		ServiceName:        envOr("SERVICE_NAME", "auth-service"),
		ServiceVersion:     envOr("SERVICE_VERSION", "dev"),
		ServiceNamespace:   envOr("SERVICE_NAMESPACE", "platform"),
		Environment:        envOr("ENVIRONMENT", "development"),
		OTLPEndpoint:       os.Getenv("OTLP_ENDPOINT"),
		MetricsAddr:        envOr("METRICS_ADDR", ":2112"),
		SSOReadyTimeout:    envDuration("SSO_READY_TIMEOUT", 2*time.Second),
		NATSHealthEnabled:  envBool("NATS_HEALTH_ENABLED", false),
		MongoHealthEnabled: envBool("MONGO_HEALTH_ENABLED", false),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
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

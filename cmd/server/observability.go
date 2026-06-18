package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/flywindy/o11y"
	"go.opentelemetry.io/otel/metric"
)

// metrics holds every application-defined instrument for the auth-service.
//
// Instruments are named in OpenTelemetry dot-notation. The SDK's Prometheus
// exporter translates them to the conventional Prometheus names shown below
// (dots → underscores, monotonic counters gain a `_total` suffix, the
// duration histogram gains a `_seconds` unit suffix):
//
//	auth.http.requests          → auth_http_requests_total
//	auth.http.request.duration  → auth_http_request_duration_seconds
//	auth.authentication         → auth_authentication_total
//	auth.token.issued           → auth_token_issued_total
//	auth.token.validation       → auth_token_validation_total
//
// Every series additionally carries the resource labels service_name,
// service_version, service_namespace and deployment_environment_name.
type metrics struct {
	httpRequests    metric.Int64Counter
	httpDuration    metric.Float64Histogram
	authentications metric.Int64Counter
	tokensIssued    metric.Int64Counter
	tokenValidation metric.Int64Counter
}

// initObservability initializes the o11y SDK and builds the application
// instruments. The returned *o11y.SDK owns a background Prometheus server (on
// oc.MetricsAddr) and the trace/log exporters; the caller must defer
// obs.Shutdown to flush them on exit.
func initObservability(ctx context.Context, oc obsConfig) (*o11y.SDK, *metrics, error) {
	opts := []o11y.Option{
		o11y.WithServiceName(oc.ServiceName),
		o11y.WithServiceVersion(oc.ServiceVersion),
		o11y.WithEnvironment(oc.Environment),
		o11y.WithServiceNamespace(oc.ServiceNamespace),
		o11y.WithMetricsAddr(oc.MetricsAddr),
	}
	if oc.OTLPEndpoint != "" {
		opts = append(opts, o11y.WithOTLPEndpoint(oc.OTLPEndpoint))
	}

	obs, err := o11y.Init(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("observability init: %w", err)
	}

	m, err := newMetrics(obs)
	if err != nil {
		_ = obs.Shutdown(ctx)
		return nil, nil, fmt.Errorf("observability metrics: %w", err)
	}

	return obs, m, nil
}

// newMetrics creates all application instruments from the SDK meter. The
// duration histogram reuses the SDK's default latency buckets so auth-service
// latency is directly comparable with the SDK-managed HTTP server histogram.
func newMetrics(obs *o11y.SDK) (*metrics, error) {
	meter := obs.Meter("auth-service")

	httpRequests, err1 := meter.Int64Counter(
		"auth.http.requests",
		metric.WithDescription("Total HTTP requests handled by the auth service."),
	)
	httpDuration, err2 := meter.Float64Histogram(
		"auth.http.request.duration",
		metric.WithDescription("Duration of HTTP requests handled by the auth service."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(o11y.DefaultLatencyBuckets()...),
	)
	authentications, err3 := meter.Int64Counter(
		"auth.authentication",
		metric.WithDescription("Total authentication attempts, by result."),
	)
	tokensIssued, err4 := meter.Int64Counter(
		"auth.token.issued",
		metric.WithDescription("Total NATS user JWTs issued."),
	)
	tokenValidation, err5 := meter.Int64Counter(
		"auth.token.validation",
		metric.WithDescription("Total SSO token validations, by result."),
	)

	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return nil, err
	}

	return &metrics{
		httpRequests:    httpRequests,
		httpDuration:    httpDuration,
		authentications: authentications,
		tokensIssued:    tokensIssued,
		tokenValidation: tokenValidation,
	}, nil
}

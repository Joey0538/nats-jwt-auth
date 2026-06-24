package main

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// httpDurationBuckets are the SRE-standard latency buckets (seconds) required
// by the ticket for auth_http_request_duration_seconds.
var httpDurationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// metrics holds every application-defined instrument. OTel dot-notation names
// map to the Prometheus names the SRE team scrapes:
//
//	auth.http.requests          → auth_http_requests_total
//	auth.http.request.duration  → auth_http_request_duration_seconds
//	auth.authentication         → auth_authentication_total
//	auth.token.issued           → auth_token_issued_total
//	auth.token.validation       → auth_token_validation_total
type metrics struct {
	httpRequests    metric.Int64Counter
	httpDuration    metric.Float64Histogram
	authentications metric.Int64Counter
	tokensIssued    metric.Int64Counter
	tokenValidation metric.Int64Counter
}

func newMetrics(meter metric.Meter) (*metrics, error) {
	httpRequests, err1 := meter.Int64Counter(
		"auth.http.requests",
		metric.WithDescription("Total HTTP requests handled by the auth service."),
	)
	httpDuration, err2 := meter.Float64Histogram(
		"auth.http.request.duration",
		metric.WithDescription("Duration of HTTP requests handled by the auth service."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(httpDurationBuckets...),
	)
	authentications, err3 := meter.Int64Counter(
		"auth.authentication",
		metric.WithDescription("Total authentication attempts, by provider and status."),
	)
	tokensIssued, err4 := meter.Int64Counter(
		"auth.token.issued",
		metric.WithDescription("Total tokens issued, by type."),
	)
	tokenValidation, err5 := meter.Int64Counter(
		"auth.token.validation",
		metric.WithDescription("Total token validations, by status."),
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

// recordHTTP increments auth_http_requests_total (labels method, path, status)
// and observes auth_http_request_duration_seconds (labels method, path).
func (m *metrics) recordHTTP(ctx context.Context, method, path string, status int, seconds float64) {
	m.httpRequests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.Int("status", status),
	))
	m.httpDuration.Record(ctx, seconds, metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("path", path),
	))
}

// recordAuthentication increments auth_authentication_total.
// provider ∈ {tsso, nats}, status ∈ {success, failure}.
func (m *metrics) recordAuthentication(ctx context.Context, provider, status string) {
	m.authentications.Add(ctx, 1, metric.WithAttributes(
		attribute.String("provider", provider),
		attribute.String("status", status),
	))
}

// recordTokenIssued increments auth_token_issued_total. typ ∈ {nats, access}.
func (m *metrics) recordTokenIssued(ctx context.Context, typ string) {
	m.tokensIssued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", typ),
	))
}

// recordTokenValidation increments auth_token_validation_total.
// status ∈ {valid, invalid, expired}.
func (m *metrics) recordTokenValidation(ctx context.Context, status string) {
	m.tokenValidation.Add(ctx, 1, metric.WithAttributes(
		attribute.String("status", status),
	))
}

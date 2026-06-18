package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// TestMetricsExposed verifies that the application instruments are created and
// surfaced on the SDK's Prometheus endpoint under their expected Prometheus
// names (dot-notation translated, with _total / _seconds suffixes).
func TestMetricsExposed(t *testing.T) {
	// Keep the test hermetic: no OTLP collector is running locally.
	t.Setenv("O11Y_TRACE_ENABLED", "false")
	t.Setenv("O11Y_LOG_ENABLED", "false")

	oc := obsConfig{
		ServiceName:      "auth-service-test",
		ServiceVersion:   "0.0.0",
		ServiceNamespace: "platform",
		Environment:      "testing",
		MetricsAddr:      "127.0.0.1:21127",
	}

	ctx := context.Background()
	obs, m, err := initObservability(ctx, oc)
	if err != nil {
		t.Fatalf("initObservability: %v", err)
	}
	defer func() { _ = obs.Shutdown(ctx) }()

	// Record one sample on every instrument.
	m.httpRequests.Add(ctx, 1, metric.WithAttributes(attribute.String("http.route", "/auth")))
	m.httpDuration.Record(ctx, 0.012, metric.WithAttributes(attribute.String("http.route", "/auth")))
	m.authentications.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "success")))
	m.tokensIssued.Add(ctx, 1)
	m.tokenValidation.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "valid")))

	body := scrapeMetrics(t, "http://127.0.0.1:21127/metrics")

	want := []string{
		"auth_http_requests_total",
		"auth_http_request_duration_seconds",
		"auth_authentication_total",
		"auth_token_issued_total",
		"auth_token_validation_total",
		`service_name="auth-service-test"`, // resource attribute became a constant label
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("metrics output missing %q", w)
		}
	}
}

func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := http.Get(url) //nolint:gosec // fixed localhost test URL
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}
	t.Fatalf("could not scrape %s: %v", url, lastErr)
	return ""
}

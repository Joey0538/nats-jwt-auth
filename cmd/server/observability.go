package main

import (
	"context"
	"fmt"

	"github.com/flywindy/o11y"
)

// initObservability initializes the o11y SDK (traces, logs, metrics) and builds
// the application instruments. The returned *o11y.SDK owns a background
// Prometheus server (on oc.MetricsAddr) and the trace/log exporters; the caller
// must defer obs.Shutdown to flush them on exit.
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

	m, err := newMetrics(obs.Meter("auth-service"))
	if err != nil {
		_ = obs.Shutdown(ctx)
		return nil, nil, fmt.Errorf("observability metrics: %w", err)
	}

	return obs, m, nil
}

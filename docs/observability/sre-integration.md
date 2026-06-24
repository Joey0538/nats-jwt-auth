# SRE Integration — auth-service

How the auth-service wires in the SRE-provided enterprise observability package.

## The package

- **Module:** `github.com/flywindy/o11y` — version **`v0.6.0`** (pinned in
  `cmd/server/go.mod`).
- **What it provides:** a single `o11y.Init` that bundles the four
  observability pillars — **traces**, **logs**, **metrics**, and optional
  **profiling** — on top of OpenTelemetry (semconv v1.39.0). It owns the
  Prometheus exposition server, the OTLP exporters, and a dual-output `slog`
  logger that auto-enriches every log line with `traceId`/`spanId`.

## Initialization

`cmd/server/observability.go` calls `o11y.Init` with the four required
identity options plus the metrics listen address:

```go
obs, err := o11y.Init(ctx,
    o11y.WithServiceName(oc.ServiceName),       // service.name
    o11y.WithServiceVersion(oc.ServiceVersion), // service.version
    o11y.WithEnvironment(oc.Environment),       // deployment.environment.name
    o11y.WithServiceNamespace(oc.ServiceNamespace), // service.namespace
    o11y.WithMetricsAddr(oc.MetricsAddr),       // Prometheus /metrics listener
)
// ... if OTLP_ENDPOINT set: o11y.WithOTLPEndpoint(...)
defer obs.Shutdown(ctx) // flush exporters on exit
slog.SetDefault(obs.Logger)
```

Application instruments are created from `obs.Meter("auth-service")` in
`cmd/server/metrics.go`.

## How `/metrics` is served

The SDK runs a **dedicated Prometheus server** on `METRICS_ADDR` (default
`:2112`), separate from the main API port. No manual handler registration is
needed; `auth_*` instruments and Go runtime metrics are exported there
automatically. Point your scrape config / `ServiceMonitor` at `:2112/metrics`.

## Naming & label conventions

OTel instruments use dot-notation; the SDK's Prometheus exporter translates
them to standard Prometheus names (dots → underscores, `_total` for counters,
`_seconds` unit suffix for the duration histogram). Instrument → exposed name:

| OTel instrument | Prometheus name |
|---|---|
| `auth.http.requests` | `auth_http_requests_total` |
| `auth.http.request.duration` | `auth_http_request_duration_seconds` |
| `auth.authentication` | `auth_authentication_total` |
| `auth.token.issued` | `auth_token_issued_total` |
| `auth.token.validation` | `auth_token_validation_total` |

Histogram buckets are pinned to the SRE-standard
`0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10` via
`metric.WithExplicitBucketBoundaries`.

## Standard labels

Resource attributes become **constant labels on every series**:
`service_name`, `service_version`, `service_namespace`,
`deployment_environment_name`. Pod/namespace/cluster labels
(`pod`, `namespace`, `cluster`) are expected to be attached by the Prometheus
scrape / relabeling layer in-cluster (not set by the app).

## Configuration (environment variables)

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Main API / probe port. |
| `METRICS_ADDR` | `:2112` | Prometheus `/metrics` listen address. |
| `SERVICE_NAME` | `auth-service` | `service.name`. |
| `SERVICE_VERSION` | `dev` | `service.version`. |
| `SERVICE_NAMESPACE` | `platform` | `service.namespace`. |
| `ENVIRONMENT` | `development` | `deployment.environment.name`. |
| `OTLP_ENDPOINT` | SDK default | OTel Collector endpoint for traces & logs. |
| `READY_TIMEOUT` | `2s` | Per-dependency readiness check timeout. |

The SDK also honors `O11Y_TRACE_ENABLED`, `O11Y_LOG_ENABLED`,
`O11Y_METRICS_ENABLED`, `O11Y_PROFILING_ENABLED`.

> **Local dev without a collector:** traces/logs export to `localhost:4318`
> will log background connection errors. Set `O11Y_TRACE_ENABLED=false` and
> `O11Y_LOG_ENABLED=false` to silence them. Metrics are pull-based and work
> standalone.

## Open items to confirm with SRE

- Where the enterprise package is canonically hosted / version policy.
- Whether `pod`/`namespace`/`cluster` come from scrape relabeling (assumed) or
  must be set by the app.
- Confirm the histogram buckets above match the org standard.

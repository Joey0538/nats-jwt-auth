# Metrics Reference — auth-service

All metrics are exposed in Prometheus format at the **`/metrics`** endpoint on
the metrics port (`METRICS_ADDR`, default `:2112`), served by the SRE
`flywindy/o11y` SDK. Every series additionally carries the resource labels
`service_name`, `service_version`, `service_namespace`,
`deployment_environment_name` (and `otel_scope_name`).

> **OTel lazy export:** a metric appears on `/metrics` only **after it has been
> recorded at least once**. A counter that has never incremented produces no
> series (not even a `0`). Generate traffic before expecting business metrics.

## Category 1 — HTTP golden signals

| Metric | Type | Labels | Description |
|---|---|---|---|
| `auth_http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests handled (health/probe paths excluded). |
| `auth_http_request_duration_seconds` | Histogram | `method`, `path` | Request latency. Buckets: `0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10`. |

- `path` is the **route template** (e.g. `/auth`), not the raw URL — keeps
  cardinality bounded.
- `status` is the numeric HTTP status code (e.g. `200`, `401`).

## Category 2 — Business-critical

| Metric | Type | Labels | Description |
|---|---|---|---|
| `auth_authentication_total` | Counter | `provider` (`tsso`\|`nats`), `status` (`success`\|`failure`) | Authentication attempts. This service authenticates against TSSO, so `provider="tsso"`. |
| `auth_token_issued_total` | Counter | `type` (`nats`\|`access`) | Tokens issued. This service issues NATS user JWTs → `type="nats"`. |
| `auth_token_validation_total` | Counter | `status` (`valid`\|`invalid`\|`expired`) | SSO token validation outcomes. |

### How the business metrics map to the `/auth` flow

| Outcome | `auth_authentication_total` | `auth_token_validation_total` | `auth_token_issued_total` |
|---|---|---|---|
| Success | `provider=tsso,status=success` | `status=valid` | `type=nats` |
| Expired token | `provider=tsso,status=failure` | `status=expired` | — |
| Invalid token | `provider=tsso,status=failure` | `status=invalid` | — |
| Access denied | `provider=tsso,status=failure` | `status=valid` (token was valid; authz failed) | — |
| Malformed request | `provider=tsso,status=failure` | — (no token validated) | — |

## Free — Go runtime metrics

`go_goroutines`, `go_gc_duration_seconds`, `process_*`, etc. come automatically
from the SDK's runtime collector — do not hand-roll them.

## Example PromQL

```promql
# Authentication failure rate (5m)
sum(rate(auth_authentication_total{status="failure"}[5m]))
  / sum(rate(auth_authentication_total[5m]))

# p95 request latency by route
histogram_quantile(0.95,
  sum(rate(auth_http_request_duration_seconds_bucket[5m])) by (le, path))

# Token validation breakdown
sum(rate(auth_token_validation_total[5m])) by (status)
```

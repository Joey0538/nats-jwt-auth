# auth-service — Observability & Health Reference (SRE)

This document is the operational reference for the `auth-service` binary
(`cmd/server`). It covers the Kubernetes health probes and the Prometheus
metrics exposed via the [`flywindy/o11y`](https://github.com/flywindy/o11y)
SDK (v0.6.0).

---

## 1. Network surface / ports

| Port | Path(s) | Purpose | Consumer |
|------|---------|---------|----------|
| `:8080` (`PORT`) | `/auth`, `/healthz/live`, `/healthz/ready` | Business API + K8s probes | App clients, kubelet |
| `:2112` (`METRICS_ADDR`) | `/metrics` | Prometheus exposition | Prometheus / scrape agent |

Metrics run on a **separate port** from the API on purpose: probe traffic and
scrapes never mix with, or get counted as, real user requests.

---

## 2. Health endpoints

### `GET /healthz/live` — liveness

Answers *"is the process alive?"* Performs **no** dependency checks (so a
flaky dependency can never trigger a pod restart).

- **Always `200`** while the process can serve HTTP.
- Body: `{"status":"alive"}`

```yaml
livenessProbe:
  httpGet: { path: /healthz/live, port: 8080 }
  initialDelaySeconds: 5
  periodSeconds: 10
```

### `GET /healthz/ready` — readiness

Answers *"can this instance serve traffic right now?"* by running every
registered dependency check.

- **`200`** when all checks pass → `{"status":"ready","checks":{"sso":"ok"}}`
- **`503`** when any check fails → `{"status":"not_ready","checks":{"sso":"unhealthy: ..."}}`

A `503` makes Kubernetes stop routing traffic **without** restarting the pod;
the instance re-enters rotation automatically once the dependency recovers.

```yaml
readinessProbe:
  httpGet: { path: /healthz/ready, port: 8080 }
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

#### Readiness dependency checks

| Check | Default | What it verifies |
|-------|---------|------------------|
| `sso` | **always on** | OIDC discovery doc (`<issuer>/.well-known/openid-configuration`) returns `200` within `SSO_READY_TIMEOUT`. This is the service's only hard runtime dependency. |
| `nats` | **off** (`NATS_HEALTH_ENABLED`) | Extensibility stub. The service signs NATS JWTs **offline** (no live connection), so there is nothing to probe yet. Enable + implement when a live NATS dependency is added. |
| `mongo` | **off** (`MONGO_HEALTH_ENABLED`) | Extensibility stub. The service does not use MongoDB today. Enable + implement when a Mongo dependency is added. |

> The NATS/Mongo checks are intentionally **off by default** so readiness never
> reports a fake "green" for a dependency it does not actually verify. The
> stubs (`newNATSChecker`, `newMongoChecker`) are wired and ready to fill in.

---

## 3. Metrics catalog

All metrics are exposed at `:2112/metrics`. Every series additionally carries
the resource labels `service_name`, `service_version`, `service_namespace`,
`deployment_environment_name`.

### Application metrics

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `auth_http_requests_total` | counter | `http_request_method`, `http_route`, `http_response_status_code` | HTTP requests handled (probes excluded). |
| `auth_http_request_duration_seconds` | histogram | `http_request_method`, `http_route`, `http_response_status_code` | HTTP request latency. Buckets: SDK default latency buckets (see §4). |
| `auth_authentication_total` | counter | `result` (`success`\|`failure`), `reason` (on failure) | Authentication attempts. `reason` ∈ `bad_request`, `token_expired`, `invalid_token`, `access_denied`, `internal`. |
| `auth_token_issued_total` | counter | — | NATS user JWTs successfully issued. |
| `auth_token_validation_total` | counter | `result` (`valid`\|`expired`\|`invalid`) | SSO token validation outcomes. |

### Also exposed (from the SDK)

- `http_server_request_duration_seconds*` — SDK-managed HTTP server histogram
  (OTel semconv v1.39.0).
- `go_*` / `process_*` — Go runtime metrics (`WithRuntimeMetrics`, default on).

> Note: `auth_http_requests_total` / `auth_http_request_duration_seconds` are
> application-defined and partially overlap the SDK's
> `http_server_request_duration_seconds`. They were requested explicitly to
> carry the `auth_` prefix; use whichever your dashboards standardize on, but
> don't double-count across both in the same panel.

---

## 4. Default histogram buckets

`auth_http_request_duration_seconds` uses `o11y.DefaultLatencyBuckets()`
(seconds):

```
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
```

---

## 5. Example PromQL (for alerts / dashboards)

```promql
# Authentication failure rate (last 5m)
sum(rate(auth_authentication_total{result="failure"}[5m]))
  / sum(rate(auth_authentication_total[5m]))

# p95 auth-service latency
histogram_quantile(0.95,
  sum(rate(auth_http_request_duration_seconds_bucket[5m])) by (le, http_route))

# Expired vs invalid token breakdown
sum(rate(auth_token_validation_total[5m])) by (result)

# JWTs issued per second
sum(rate(auth_token_issued_total[5m]))
```

---

## 6. Configuration (environment variables)

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | `8080` | Main API / probe port. |
| `METRICS_ADDR` | `:2112` | Prometheus `/metrics` listen address. |
| `SERVICE_NAME` | `auth-service` | OTel `service.name`. |
| `SERVICE_VERSION` | `dev` | OTel `service.version`. |
| `SERVICE_NAMESPACE` | `platform` | OTel `service.namespace`. |
| `ENVIRONMENT` | `development` | OTel `deployment.environment.name` (`production`/`staging`/`development`/`testing`). |
| `OTLP_ENDPOINT` | `http://localhost:4318` | OTel Collector endpoint for **traces & logs**. |
| `SSO_READY_TIMEOUT` | `2s` | Timeout for the readiness SSO check. |
| `NATS_HEALTH_ENABLED` | `false` | Register the NATS readiness check. |
| `MONGO_HEALTH_ENABLED` | `false` | Register the Mongo readiness check. |

The SDK also honors `O11Y_TRACE_ENABLED`, `O11Y_LOG_ENABLED`,
`O11Y_METRICS_ENABLED`, `O11Y_PROFILING_ENABLED`.

> **Local development without an OTel Collector:** traces/logs export to
> `localhost:4318` will log background connection errors. Set
> `O11Y_TRACE_ENABLED=false` and `O11Y_LOG_ENABLED=false` to silence them.
> Metrics are pull-based and work standalone — no collector needed.

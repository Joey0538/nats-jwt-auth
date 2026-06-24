# Local Observability Stack — Prometheus + Grafana

Brings up Prometheus (scrape) and Grafana (dashboards) to visualize the
auth-service metrics exposed by the `flywindy/o11y` SDK at `:2112/metrics`.

```
auth-service :2112/metrics  ──scrape──►  Prometheus :9090  ──datasource──►  Grafana :3000
```

## Run

```bash
# 1. Start the auth-service so its metrics port is reachable on the host:
METRICS_ADDR=:2112 PORT=8080 \
OIDC_ISSUER_URL=... OIDC_AUDIENCE=... NATS_ACCOUNT_SEED=SA... \
./auth-service

# 2. Bring up the stack:
cd docker-local/observability
docker compose up -d
```

| Service | URL | Notes |
|---|---|---|
| Prometheus | http://localhost:9090 | Targets: Status → Targets (auth-service should be `UP`) |
| Grafana | http://localhost:3000 | Login `admin` / `admin`; dashboard **Auth Service — Observability** is auto-provisioned |

> Prometheus scrapes the auth-service via `host.docker.internal:2112`
> (the host-gateway is wired in `docker-compose.yml`). If you run the
> auth-service inside this compose network instead, change the target in
> `prometheus/prometheus.yml` to `auth-service:2112`.

## What's provisioned

- **`prometheus/prometheus.yml`** — scrape job `auth-service` (5s interval).
- **`grafana/provisioning/datasources/`** — Prometheus datasource (uid `prometheus`).
- **`grafana/provisioning/dashboards/`** + **`grafana/dashboards/auth-service.json`** —
  a dashboard with panels for the HTTP golden signals, authentication outcomes,
  token validation/issuance, failure ratio, and Go runtime.

## Note on lazy metrics

OTel only exports a metric **after it has been recorded at least once**. So
`auth_*` series appear in Prometheus/Grafana only once the corresponding traffic
has hit the service. Send a few requests to `/auth` before expecting data
(`auth_token_issued_total` needs a *successful* authentication).

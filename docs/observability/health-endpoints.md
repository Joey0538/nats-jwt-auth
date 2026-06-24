# Health Endpoints — auth-service

The service exposes Kubernetes-standard probes on the **main API port**
(`PORT`, default `8080`), plus a backward-compatible legacy endpoint.

| Endpoint | Purpose | Checks deps? |
|---|---|---|
| `GET /healthz/live` | Liveness | No |
| `GET /healthz/ready` | Readiness | Yes (MongoDB, NATS, TSSO) |
| `GET /health` | Legacy (backward compatibility) | No |

## `GET /healthz/live` — liveness

Answers *"is the process alive?"* Performs **no** dependency checks, so it is
cheap (**< 100 ms**) and a failing dependency can never trigger a pod restart.

- Always `200` while the process can serve HTTP.
- Body: `{"status":"alive"}`

## `GET /healthz/ready` — readiness

Answers *"can this instance serve traffic right now?"* by running every
registered dependency check (all run in one pass, so the response shows each
dependency's status even if one fails).

- **`200`** — all healthy:
  ```json
  {"status":"ready","checks":{"mongodb":"ok","nats":"ok","tsso":"ok"}}
  ```
- **`503`** — any failure (failing dep marked `"failed"`):
  ```json
  {"status":"not_ready","checks":{"mongodb":"failed","nats":"ok","tsso":"ok"}}
  ```

A `503` makes Kubernetes pull the pod from the load balancer **without**
restarting it; it re-enters rotation automatically once the dependency recovers.

### Dependency checks

| Check (`name`) | What it verifies |
|---|---|
| `tsso` | OIDC discovery doc (`<issuer>/.well-known/openid-configuration`) returns `200` within `READY_TIMEOUT`. |
| `mongodb` | `Ping` on the injected Mongo client succeeds within `READY_TIMEOUT`. |
| `nats` | Injected NATS connection reports `IsConnected() == true`. |

Checks are modeled behind the `Checker` interface and injected, so each is
unit-tested with fakes independent of a live dependency. In this repository only
`tsso` has a live client wired by default; `mongodb`/`nats` checkers activate
once their clients are injected in `main` (see `health.go`).

## `GET /health` — legacy

Unchanged from the original service for backward compatibility.

- `200`, body: `{"status":"ok"}`

## Recommended Kubernetes probe config

```yaml
livenessProbe:
  httpGet: { path: /healthz/live, port: 8080 }
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet: { path: /healthz/ready, port: 8080 }
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

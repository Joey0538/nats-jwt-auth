# nats-jwt-auth

A reusable Go package for issuing NATS user JWTs via decentralized JWT auth. Teams plug in their own OIDC provider and permissions logic — the library handles everything else.

## Why this exists

In a chat system with 1000-member rooms, the naive O(N) fanout (one publish per user) chokes the backend. The goal is O(1) publish — worker publishes once to `room.123`, NATS fans it out to all subscribers.

For that to work, each client must subscribe directly to `room.123` on NATS, which means they need per-room permissions. This library issues those permissions as NATS user JWTs, validated cryptographically by NATS — **no auth callout on reconnect**, no thundering herd.

### Decentralized JWT vs Auth Callout

| | Auth Callout | Decentralized JWT (this pkg) |
|---|---|---|
| Reconnect | Hits your auth service every time | Validated locally by NATS |
| Thundering herd | 10K reconnects = 10K HTTP calls | Eliminated — only initial login + expiry |
| Frontend complexity | None (NATS calls your service) | Generates ephemeral Ed25519 keypair |
| Private key location | N/A | Browser RAM only — never transmitted |

## Architecture

```
Frontend                    Auth Service (this pkg)           NATS Server
   |                              |                              |
   | 1. Generate Ed25519 keypair  |                              |
   |    (createUser() from nkeys) |                              |
   |                              |                              |
   | 2. POST /auth -------------->|                              |
   |    { sso_token, nats_pub_key }                              |
   |                              |                              |
   |                        3. Validate SSO token (OIDC JWKS)    |
   |                        4. PermissionsProvider -> rooms/ACLs  |
   |                        5. Sign NATS JWT (account seed)      |
   |                              |                              |
   | <--- { nats_jwt } ----------|                              |
   |                              |                              |
   | 6. Connect to NATS ---------------------------------------->|
   |    jwtAuthenticator(jwt, seed)                              |
   |                              |   7. Verify JWT signature    |
   |                              |      Challenge nonce         |
   | <--------------------------------- Connected ---------------|
```

## Prerequisites

- **Docker** — required for local development (Keycloak, NATS, and key generation)
- **Go 1.25+** — `go version` should be 1.25 or later

The `setup.sh` script uses the [`nats-box`](https://github.com/nats-io/nats-box) Docker image for all NATS key generation (`nsc`, `nk`), so **no local NATS tooling installation is needed**. Works identically on macOS, Ubuntu, and any OS with Docker.

> **Optional:** If you want the NATS CLI tools installed locally (for debugging, inspecting keys, etc.):
>
> ```bash
> # macOS
> brew tap nats-io/nats-tools
> brew install nats-io/nats-tools/nsc nats-io/nats-tools/nats
> go install github.com/nats-io/nkeys/nk@latest
>
> # Ubuntu / Linux — use nats-box instead
> docker run --rm -it natsio/nats-box:latest
> ```

## Local Development (quickest path)

The `setup.sh` script generates all NATS keys via the `nats-box` Docker image, then writes the `.env` and `nats.conf` files for you. One command to get everything running — no local `nsc` or `nk` needed.

### Step 1: Run setup

```bash
cd docker-local/auth-service
./setup.sh
```

This creates:
- `.env` — all env vars for the auth service (OIDC, NATS keys)
- `nats.conf` — NATS server config with baked-in operator + account JWTs

> **Important:** If you re-run `setup.sh` (new keys), you MUST also restart the Docker containers (`docker compose down && docker compose up -d`) so NATS picks up the new `nats.conf`. Mismatched keys = "Authorization Violation".

### Step 2: Start Keycloak + NATS

```bash
docker compose up -d

# Wait for Keycloak to be ready (~30-60s)
curl -s http://localhost:9090/realms/chatapp/.well-known/openid-configuration | head -1
# Should return JSON — if empty, Keycloak is still starting
```

### Step 3: Start the auth service (on host)

```bash
set -a && source .env && set +a && go run ../../cmd/server
```

> **Why on host, not Docker?** The OIDC issuer in Keycloak tokens is `http://localhost:9090/realms/chatapp`. go-oidc strictly validates that the discovery URL matches the token issuer. Running on host means auth-service reaches Keycloak at the same `localhost:9090` URL that browsers use — no issuer mismatch. The Dockerfile is for deployment.

### Step 4: Start the frontend

```bash
cd ../../examples/frontend
npm install
npm run dev
# Open http://localhost:3000, click "Login with Keycloak"
# Login as testuser/testuser or alice/alice
```

### Step 5: Test via curl (optional)

```bash
# Get a test token from Keycloak (password grant, dev only)
# Note: Keycloak ID tokens expire in 5 minutes — run this as one command
TOKEN=$(curl -s -X POST "http://localhost:9090/realms/chatapp/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=nats-chat" \
  -d "username=testuser" \
  -d "password=testuser" \
  -d "scope=openid" | python3 -c "import sys,json; print(json.load(sys.stdin)['id_token'])")

# Generate a NATS user keypair (via nats-box — no local nk needed)
PUB=$(docker run --rm natsio/nats-box:latest sh -c "nk -gen user | nk -inkey /dev/stdin -pubout")

# Call the auth service
curl -s -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d "{\"sso_token\": \"$TOKEN\", \"nats_public_key\": \"$PUB\"}" | python3 -m json.tool
```

Response:

```json
{
  "nats_jwt": "eyJ...",
  "user": {
    "sub": "1d85aa54-c9f5-4310-9663-1fac741e9ecc",
    "email": "testuser@example.com",
    "name": "Test User",
    "preferred_username": "testuser",
    "given_name": "Test",
    "family_name": "User"
  }
}
```

If the SSO token has expired:

```json
{ "message": "SSO token has expired, please re-login" }  // 401
```

### Service URLs

| Service | URL |
|---|---|
| Keycloak Admin | http://localhost:9090 (admin / admin) |
| Auth Service | http://localhost:8080/health |
| NATS Client | localhost:4222 |
| NATS Monitoring | http://localhost:8222 |
| NATS WebSocket | ws://localhost:9222 |
| Frontend | http://localhost:3000 |

### Test users (pre-configured in Keycloak)

| Username | Password | Email |
|---|---|---|
| testuser | testuser | testuser@example.com |
| alice | alice | alice@example.com |

## NATS Key Setup (from scratch)

If you're not using `setup.sh` and need to understand the key hierarchy:

NATS uses a 3-layer trust hierarchy:

```
Operator  (top-level trust anchor, runs the NATS cluster)
  +-- Account  (your team's namespace -- SA... seed)
        +-- User  (individual client JWTs, issued by this library)
```

### Create operator + account

All `nsc` commands can be run via nats-box if you don't have `nsc` installed locally:

```bash
# Option A: local nsc (if installed)
nsc add operator --name myoperator --sys
nsc env -o myoperator
nsc add account --name chatapp

# Option B: nats-box (works everywhere)
docker run --rm -it -v $(pwd)/nsc-output:/output natsio/nats-box:latest sh -c '
  nsc add operator --name myoperator --sys
  nsc env -o myoperator
  nsc add account --name chatapp
  nsc describe operator --raw > /output/operator.jwt
  nsc describe account chatapp --raw > /output/account.jwt
  nsc describe account SYS --raw > /output/sys.jwt
'
```

### Extract values

```bash
# Operator JWT -- goes into nats.conf
nsc describe operator --raw

# Account JWT -- goes into nats.conf resolver_preload
nsc describe account chatapp --raw

# Account public key
nsc describe account chatapp 2>&1 | grep "Account ID"

# SYS account (needed for resolver_preload too)
nsc describe account SYS --raw
nsc describe account SYS 2>&1 | grep "Account ID"

# Account seed (SA...) -- goes into NATS_ACCOUNT_SEED env var
# nsc stores seeds on disk:
cat ~/.local/share/nats/nsc/keys/keys/A/<first-2-chars>/<FULL_ACCOUNT_PUBLIC_KEY>.nk
# Outputs: SAAM...
# This is a secret. Do not commit to version control.
```

### Write nats.conf

```hcl
port: 4222
http_port: 8222

operator: <OPERATOR_JWT>

resolver: MEMORY

resolver_preload {
  <CHATAPP_ACCOUNT_PUB_KEY>: <CHATAPP_ACCOUNT_JWT>
  <SYS_ACCOUNT_PUB_KEY>: <SYS_ACCOUNT_JWT>
}

websocket {
  port: 9222
  no_tls: true  # dev only
}
```

> **Note:** the field is `resolver_preload` (no trailing 's'), and it must include both your app account AND the SYS account.

## Package Structure

The library is split into independent Go modules so teams only download what they need:

| Import path | What it provides | Direct deps |
|---|---|---|
| `github.com/joey0538/nats-jwt-auth` | `Authenticator`, `Config`, typed errors, `PermissionsProvider` | go-oidc, nats-io/jwt, nats-io/nkeys |
| `github.com/joey0538/nats-jwt-auth/echoserver` | Batteries-included Echo HTTP server | core + echo |
| `github.com/joey0538/nats-jwt-auth/viperconfig` | `LoadConfig()` from env vars / .env files | core + viper + mapstructure |

Teams using Gin, Chi, or net/http import **only the core** — no Echo or Viper in their dependency tree.

## Customization Guide

Every team uses the same library but customises these things. See `examples/` for complete runnable code.

### 1. Config loading

```go
// Option A: viperconfig.LoadConfig() — reads env vars + .env files. Zero boilerplate.
import "github.com/joey0538/nats-jwt-auth/viperconfig"
cfg, err := viperconfig.LoadConfig()

// Option B: Build manually — full control, no Viper dependency.
cfg := natsauth.Config{
    OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
    OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
    NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
    NATSJWTExpiry:   15 * time.Minute,  // default: 1h
    Port:            "9090",             // default: "8080"
}
```

### 2. PermissionsProvider (the main thing teams customise)

**Pattern A: Inline function** — quick and simple, good for straightforward logic.

```go
natsauth.WithPermissionsProvider(
    natsauth.PermissionsProviderFunc(func(ctx context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
        rooms, err := db.GetRoomsForUser(ctx, user.Subject)
        if err != nil {
            return natsauth.Permissions{}, err
        }
        subs := make([]string, len(rooms))
        for i, r := range rooms {
            subs[i] = fmt.Sprintf("room.%s", r)
        }
        return natsauth.Permissions{PubAllow: subs, SubAllow: subs}, nil
    }),
)
```

**Pattern B: Full struct** — when logic is complex, needs dependencies (DB, cache), or you want it testable.

```go
type DBPermissionsProvider struct {
    db *sql.DB
}

func (p *DBPermissionsProvider) GetPermissions(ctx context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
    rows, err := p.db.QueryContext(ctx, "SELECT room_id FROM room_members WHERE user_id = $1", user.Subject)
    // ... build permissions from DB results
}

// Pass it in:
natsauth.WithPermissionsProvider(&DBPermissionsProvider{db: db})
```

**Pattern C: Role-based from SSO claims** — use roles/groups from the OIDC token.

```go
func (p *RoleBasedProvider) GetPermissions(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
    // Keycloak roles live in user.Extra["realm_access"]["roles"]
    // Okta groups live in user.Extra["groups"]
    roles := extractRoles(user.Extra)

    var pub, sub []string
    for _, role := range roles {
        switch role {
        case "admin":
            pub = append(pub, ">")    // admin can publish to everything
            sub = append(sub, ">")    // admin can subscribe to everything
        case "user":
            sub = append(sub, "room.general", "room.announcements")
            pub = append(pub, "room.general")
        case "engineering":
            sub = append(sub, "room.engineering", "deploy.>")
            pub = append(pub, "room.engineering")
        }
    }
    return natsauth.Permissions{PubAllow: pub, SubAllow: sub}, nil
}
```

See `examples/role-based/` for the complete implementation with role extraction helpers.

### 3. Permissions — Allow, Deny, and Wildcards

```go
natsauth.Permissions{
    // What this user CAN do
    PubAllow: []string{"room.general", "room.engineering", "user.alice.>"},
    SubAllow: []string{"room.>", "user.alice.>"},  // room.> = all rooms

    // What this user CANNOT do (deny overrides allow)
    PubDeny: []string{"room.announcements"},  // read-only channel
    SubDeny: []string{"$SYS.>"},              // block system subjects
}
```

NATS wildcard rules:
- `room.>` matches `room.general`, `room.eng.frontend`, etc. (multi-level)
- `room.*` matches `room.general` but NOT `room.eng.frontend` (single level)
- `>` matches everything

Deny always wins over Allow.

### 4. Rejecting users (403 vs 500)

Return `ErrAccessDenied` or `NewAccessDeniedError("reason")` from your `PermissionsProvider` to reject a user with **403 Forbidden**. Any other error returns **500 Internal Server Error**.

```go
func (p *MyProvider) GetPermissions(ctx context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
    // User is banned → 403
    if isBanned(user.Subject) {
        return natsauth.Permissions{}, natsauth.NewAccessDeniedError("account is deactivated")
    }

    // DB is down → 500
    rooms, err := db.GetRooms(ctx, user.Subject)
    if err != nil {
        return natsauth.Permissions{}, err
    }

    // No rooms → 403
    if len(rooms) == 0 {
        return natsauth.Permissions{}, natsauth.NewAccessDeniedError("no rooms assigned")
    }

    return natsauth.Permissions{PubAllow: rooms, SubAllow: rooms}, nil
}
```

Response on 403: `{ "message": "natsauth: access denied: account is deactivated" }`

### 5. UserClaims — what you get from the SSO token

```go
func myProvider(ctx context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
    user.Subject          // "1d85aa54-c9f5-4310-..."  — unique ID
    user.Email            // "alice@company.com"
    user.Name             // "Alice Engineer"
    user.PreferredUsername // "alice"
    user.GivenName        // "Alice"
    user.FamilyName       // "Engineer"
    user.Extra            // map[string]any — custom OIDC claims (roles, groups, department, etc.)

    // Access Keycloak realm roles:
    realmAccess := user.Extra["realm_access"].(map[string]any)
    roles := realmAccess["roles"].([]any)  // ["user", "admin"]

    // Access Okta groups:
    groups := user.Extra["groups"].([]any) // ["engineering", "platform"]
}
```

### 6. Logger

```go
// Default: JSON to stdout
// Override with any *slog.Logger:

// Text format to stderr with debug level
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
natsauth.WithLogger(logger)

// JSON to a file
f, _ := os.OpenFile("auth.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
logger := slog.New(slog.NewJSONHandler(f, nil))
natsauth.WithLogger(logger)
```

### 7. Using Authenticator directly (any framework)

```go
// No Echo dependency — use Gin, Chi, net/http, or anything else.
auth, err := natsauth.NewAuthenticator(ctx, cfg,
    natsauth.WithPermissionsProvider(myProvider),
)

// In your handler:
result, err := auth.Authenticate(ctx, ssoToken, natsPublicKey)
// result.NATSJWT  — signed NATS JWT
// result.User     — validated identity from SSO

// Map errors to HTTP status codes:
//   errors.Is(err, natsauth.ErrMissingToken)  → 400
//   errors.Is(err, natsauth.ErrTokenExpired)   → 401
//   errors.Is(err, natsauth.ErrAccessDenied)   → 403
```

See `examples/gin/` and `examples/net-http/` for complete framework-agnostic examples.

### 8. Echo server (batteries-included)

```go
import "github.com/joey0538/nats-jwt-auth/echoserver"

// Option A: Standalone — blocks until SIGTERM.
srv, err := echoserver.New(ctx, cfg, natsauth.WithPermissionsProvider(myProvider))
srv.Run()

// Option B: Mount into existing Echo server.
srv.MountOn(e, "/nats")  // adds POST /nats/auth + GET /nats/health
```

### 9. Putting it all together

```go
import (
    natsauth "github.com/joey0538/nats-jwt-auth"
    "github.com/joey0538/nats-jwt-auth/echoserver"
    "github.com/joey0538/nats-jwt-auth/viperconfig"
)

cfg, err := viperconfig.LoadConfig()
srv, err := echoserver.New(ctx, cfg,
    natsauth.WithLogger(myLogger),
    natsauth.WithPermissionsProvider(&MyDBProvider{db: db}),
)
```

See `examples/echo-full/` for a single file showing every override together.

### Runnable examples

| Example | Path | What it shows |
|---|---|---|
| Basic | `examples/basic/` | viperconfig + echoserver + inline permissions |
| Echo mount | `examples/echo-mount/` | Embedding into existing Echo server |
| Echo full | `examples/echo-full/` | Every override + MountOn |
| Role-based | `examples/role-based/` | SSO roles/groups to NATS permissions |
| Gin | `examples/gin/` | Gin framework + custom response format |
| net/http | `examples/net-http/` | stdlib net/http, zero framework deps |
| Frontend | `examples/frontend/` | Next.js + Keycloak + NATS WebSocket |

## Room Invites (mid-session permission update)

NATS permissions are locked at connection time. When a user gets invited to a new room mid-session:

1. Add the room to their permissions in your DB
2. Kick **only** the invited user (not all room members) via `$SYS.REQ.SERVER.<id>.KICK`
3. The client auto-reconnects, auth fires again, fresh JWT includes the new room
4. Done. O(1) operation.

## API Reference

### Config

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `Port` | `string` | No | `"8080"` | HTTP listen port (echoserver only) |
| `OIDCIssuerURL` | `string` | Yes | -- | OIDC discovery URL |
| `OIDCAudience` | `string` | Yes | -- | OIDC client_id |
| `NATSAccountSeed` | `string` | Yes | -- | `SA...` account private seed |
| `NATSJWTExpiry` | `time.Duration` | No | `1h` | JWT lifetime |
| `TLSSkipVerify` | `bool` | No | `false` | Skip TLS cert verification for OIDC issuer (dev only) |
| `OIDCDiscoveryTimeout` | `time.Duration` | No | `10s` | Max time for OIDC issuer discovery |

### viperconfig.LoadConfig()

Reads config from environment variables via Viper. Also checks `.env` files in current directory and `/etc/nats-auth/`. Import `github.com/joey0538/nats-jwt-auth/viperconfig`.

```go
cfg, err := viperconfig.LoadConfig()
```

| Env Var | Maps To |
|---|---|
| `OIDC_ISSUER_URL` | `Config.OIDCIssuerURL` |
| `OIDC_AUDIENCE` | `Config.OIDCAudience` |
| `NATS_ACCOUNT_SEED` | `Config.NATSAccountSeed` |
| `NATS_JWT_EXPIRY` | `Config.NATSJWTExpiry` |
| `PORT` | `Config.Port` |
| `TLS_SKIP_VERIFY` | `Config.TLSSkipVerify` |
| `OIDC_DISCOVERY_TIMEOUT` | `Config.OIDCDiscoveryTimeout` |

### Options

| Option | Description |
|---|---|
| `WithPermissionsProvider(p)` | Custom room/ACL lookup. Default: allows `chat.>` and `user.<sub>.>` |
| `WithLogger(l)` | Custom `*slog.Logger` |

### PermissionsProvider interface

```go
type PermissionsProvider interface {
    GetPermissions(ctx context.Context, user UserClaims) (Permissions, error)
}
```

Use `PermissionsProviderFunc` for inline functions.

### POST /auth response

```json
{
  "nats_jwt": "eyJ...",
  "user": {
    "sub": "uuid-from-sso",
    "email": "user@example.com",
    "name": "Full Name",
    "preferred_username": "username",
    "given_name": "First",
    "family_name": "Last"
  }
}
```

If the SSO token is expired, returns `401`:

```json
{ "message": "SSO token has expired, please re-login" }
```

### UserClaims

```go
type UserClaims struct {
    Subject          string                 // unique user ID from SSO
    Email            string                 // from OIDC token
    Name             string                 // full display name
    PreferredUsername string                 // login username
    GivenName        string                 // first name
    FamilyName       string                 // last name
    Extra            map[string]interface{} // additional OIDC claims
}
```

### Permissions

```go
type Permissions struct {
    PubAllow []string  // subjects user can publish to
    SubAllow []string  // subjects user can subscribe to
    PubDeny  []string  // explicitly blocked publish subjects
    SubDeny  []string  // explicitly blocked subscribe subjects
}
```

## Project Structure

```
nats-jwt-auth/
├── go.mod                         # Core module (3 deps: go-oidc, nats-io/jwt, nats-io/nkeys)
├── authenticator.go               # Authenticator — framework-agnostic core
├── config.go                      # Config struct (no Viper dependency)
├── errors.go                      # Typed sentinel errors for HTTP status mapping
├── permissions.go                 # PermissionsProvider interface
├── internal/
│   ├── oidc/validator.go          # OIDC token verification against SSO JWKS
│   └── jwt/signer.go             # NATS JWT signing with account keypair
├── echoserver/                    # Separate module: batteries-included Echo server
│   ├── go.mod
│   └── server.go                  # Server.Run(), Server.MountOn()
├── viperconfig/                   # Separate module: env var + .env config loading
│   ├── go.mod
│   └── config.go                  # LoadConfig() via Viper
├── cmd/server/                    # Standalone binary (echoserver + viperconfig)
│   ├── go.mod
│   └── main.go
├── examples/
│   ├── go.mod                     # Shared by all Go examples
│   ├── basic/main.go             # viperconfig + echoserver + inline permissions
│   ├── echo-mount/main.go        # Embed into existing Echo server
│   ├── echo-full/main.go         # Every override in one place
│   ├── role-based/main.go        # SSO roles/groups → NATS permissions
│   ├── gin/main.go               # Gin framework + custom response format
│   ├── net-http/main.go          # stdlib net/http, zero framework
│   └── frontend/                  # Next.js chat demo (Keycloak + NATS)
└── docker-local/auth-service/
    ├── setup.sh                   # Generates NATS keys + .env + nats.conf
    ├── compose.yml                # Keycloak + NATS
    ├── keycloak/realm-export.json # Pre-configured realm, client, test users
    ├── Dockerfile                 # Multi-stage alpine build (for deployment)
    └── .env.example               # All env vars documented
```

`internal/` is intentional — other teams import the public API (`natsauth.NewAuthenticator`, `natsauth.Config`, etc.) and cannot accidentally depend on implementation details.

Each submodule (`echoserver/`, `viperconfig/`, `examples/gin/`, `examples/net-http/`) has its own `go.mod` with `replace` directives for local development. Teams only download the dependencies they actually import.

## Frontend Integration (browser)

See `examples/frontend/` for a complete Next.js demo. The key flow:

```typescript
import { createUser } from "nkeys.js";
import { connect, jwtAuthenticator } from "nats.ws";

// 1. Generate ephemeral keypair (private key stays in browser RAM)
const user = createUser();
const publicKey = user.getPublicKey();
const seed = user.getSeed();

// 2. Get NATS JWT from your auth service
const res = await fetch("/auth", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    sso_token: ssoToken,        // from your OIDC login flow
    nats_public_key: publicKey,  // U... public key
  }),
});
const { nats_jwt } = await res.json();

// 3. Connect to NATS
const nc = await connect({
  servers: "ws://localhost:9222",
  authenticator: jwtAuthenticator(nats_jwt, seed),
});

// 4. Subscribe to rooms
const sub = nc.subscribe("room.general");
for await (const msg of sub) {
  console.log(new TextDecoder().decode(msg.data));
}
```

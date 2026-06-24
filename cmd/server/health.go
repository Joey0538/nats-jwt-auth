package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Checker reports the health of a single critical dependency. Implementations
// must be cheap and bounded (apply their own timeout) so the readiness probe
// can never hang. Modeling checks behind this interface keeps the readiness
// logic unit-testable with fakes, independent of real MongoDB/NATS/TSSO.
type Checker interface {
	// Name is the stable key used in the readiness response (e.g. "mongodb").
	Name() string
	// Check returns nil when healthy, or an error explaining why not.
	Check(ctx context.Context) error
}

// Report is the aggregated result of running every readiness Checker.
type Report struct {
	Healthy bool
	Checks  map[string]string // name → "ok" | "failed"
}

// Health aggregates the readiness Checkers for the service.
type Health struct {
	checkers []Checker
}

// NewHealth builds a Health aggregator from the given checkers.
func NewHealth(checkers ...Checker) *Health {
	return &Health{checkers: checkers}
}

// Check runs every checker (regardless of earlier failures) and returns the
// aggregated Report so the response shows each dependency's status in one pass.
func (h *Health) Check(ctx context.Context) Report {
	report := Report{Healthy: true, Checks: make(map[string]string, len(h.checkers))}
	for _, c := range h.checkers {
		if err := c.Check(ctx); err != nil {
			report.Checks[c.Name()] = "failed"
			report.Healthy = false
			continue
		}
		report.Checks[c.Name()] = "ok"
	}
	return report
}

// ---------------------------------------------------------------------------
// TSSO (OIDC) — reachability of the SSO discovery endpoint.
// ---------------------------------------------------------------------------

// TSSOChecker verifies the OIDC/SSO provider is reachable by fetching its
// discovery document — the auth-service's only hard runtime dependency here.
type TSSOChecker struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func NewTSSOChecker(issuerURL string, timeout time.Duration) *TSSOChecker {
	return &TSSOChecker{
		url:     strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration",
		client:  http.DefaultClient,
		timeout: timeout,
	}
}

func (c *TSSOChecker) Name() string { return "tsso" }

func (c *TSSOChecker) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MongoDB — ping the database.
// ---------------------------------------------------------------------------

// MongoPinger is the minimal surface the MongoChecker needs. The real
// *mongo.Client satisfies this via a thin adapter; tests use a fake.
type MongoPinger interface {
	Ping(ctx context.Context) error
}

// MongoChecker reports MongoDB health by issuing a ping.
type MongoChecker struct {
	pinger  MongoPinger
	timeout time.Duration
}

func NewMongoChecker(pinger MongoPinger, timeout time.Duration) *MongoChecker {
	return &MongoChecker{pinger: pinger, timeout: timeout}
}

func (c *MongoChecker) Name() string { return "mongodb" }

func (c *MongoChecker) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.pinger.Ping(ctx)
}

// ---------------------------------------------------------------------------
// NATS — connection status.
// ---------------------------------------------------------------------------

// NATSConn is the minimal surface the NATSChecker needs. The real *nats.Conn
// satisfies IsConnected(); tests use a fake.
type NATSConn interface {
	IsConnected() bool
}

// NATSChecker reports NATS health by inspecting the live connection status.
type NATSChecker struct {
	conn NATSConn
}

func NewNATSChecker(conn NATSConn) *NATSChecker {
	return &NATSChecker{conn: conn}
}

func (c *NATSChecker) Name() string { return "nats" }

func (c *NATSChecker) Check(_ context.Context) error {
	if !c.conn.IsConnected() {
		return errors.New("nats: not connected")
	}
	return nil
}

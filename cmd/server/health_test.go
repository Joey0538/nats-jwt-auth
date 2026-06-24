package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// --- fakes for interface-injected checkers ---------------------------------

type fakeChecker struct {
	name string
	err  error
}

func (f fakeChecker) Name() string                { return f.name }
func (f fakeChecker) Check(context.Context) error { return f.err }

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

type fakeNATS struct{ connected bool }

func (f fakeNATS) IsConnected() bool { return f.connected }

// --- Health aggregation -----------------------------------------------------

func TestHealthAllHealthy(t *testing.T) {
	h := NewHealth(
		fakeChecker{name: "mongodb"},
		fakeChecker{name: "nats"},
		fakeChecker{name: "tsso"},
	)
	report := h.Check(context.Background())

	if !report.Healthy {
		t.Fatalf("expected healthy, got %+v", report)
	}
	for _, name := range []string{"mongodb", "nats", "tsso"} {
		if report.Checks[name] != "ok" {
			t.Errorf("check %q = %q, want \"ok\"", name, report.Checks[name])
		}
	}
}

func TestHealthMongoDown(t *testing.T) {
	h := NewHealth(
		fakeChecker{name: "mongodb", err: errors.New("connection refused")},
		fakeChecker{name: "nats"},
		fakeChecker{name: "tsso"},
	)
	report := h.Check(context.Background())

	if report.Healthy {
		t.Fatal("expected unhealthy when mongodb is down")
	}
	if report.Checks["mongodb"] != "failed" {
		t.Errorf("mongodb = %q, want \"failed\"", report.Checks["mongodb"])
	}
	if report.Checks["nats"] != "ok" || report.Checks["tsso"] != "ok" {
		t.Errorf("expected nats/tsso ok, got %+v", report.Checks)
	}
}

// --- individual checkers ----------------------------------------------------

func TestTSSOChecker(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	if err := NewTSSOChecker(ok.URL, time.Second).Check(context.Background()); err != nil {
		t.Errorf("reachable TSSO: unexpected error %v", err)
	}
	if err := NewTSSOChecker(bad.URL, time.Second).Check(context.Background()); err == nil {
		t.Error("TSSO returning 500: expected error, got nil")
	}
	if err := NewTSSOChecker("http://127.0.0.1:0", time.Second).Check(context.Background()); err == nil {
		t.Error("unreachable TSSO: expected error, got nil")
	}
}

func TestMongoChecker(t *testing.T) {
	if err := NewMongoChecker(fakePinger{}, time.Second).Check(context.Background()); err != nil {
		t.Errorf("healthy mongo: unexpected error %v", err)
	}
	if err := NewMongoChecker(fakePinger{err: errors.New("no reachable servers")}, time.Second).Check(context.Background()); err == nil {
		t.Error("down mongo: expected error, got nil")
	}
}

func TestNATSChecker(t *testing.T) {
	if err := NewNATSChecker(fakeNATS{connected: true}).Check(context.Background()); err != nil {
		t.Errorf("connected nats: unexpected error %v", err)
	}
	if err := NewNATSChecker(fakeNATS{connected: false}).Check(context.Background()); err == nil {
		t.Error("disconnected nats: expected error, got nil")
	}
}

// --- HTTP handlers ----------------------------------------------------------

func newTestApp(checkers ...Checker) *app {
	return &app{health: NewHealth(checkers...)}
}

func TestHandleLive(t *testing.T) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/healthz/live", nil), rec)

	if err := newTestApp().handleLive(c); err != nil {
		t.Fatalf("handleLive error: %v", err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"alive"`) {
		t.Fatalf("liveness = %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandleReady(t *testing.T) {
	tests := []struct {
		name       string
		checkers   []Checker
		wantStatus int
		wantBody   string
	}{
		{
			name:       "all healthy",
			checkers:   []Checker{fakeChecker{name: "mongodb"}, fakeChecker{name: "nats"}, fakeChecker{name: "tsso"}},
			wantStatus: http.StatusOK,
			wantBody:   `"ready"`,
		},
		{
			name:       "mongo down",
			checkers:   []Checker{fakeChecker{name: "mongodb", err: errors.New("boom")}},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `"mongodb":"failed"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(http.MethodGet, "/healthz/ready", nil), rec)

			if err := newTestApp(tt.checkers...).handleReady(c); err != nil {
				t.Fatalf("handleReady error: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want contains %s", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHandleHealthLegacy(t *testing.T) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/health", nil), rec)

	if err := newTestApp().handleHealthLegacy(c); err != nil {
		t.Fatalf("handleHealthLegacy error: %v", err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("legacy health = %d %q", rec.Code, rec.Body.String())
	}
}

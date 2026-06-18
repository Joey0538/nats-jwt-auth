package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHandleLive(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/healthz/live", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handleLive(c); err != nil {
		t.Fatalf("handleLive returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"alive"`) {
		t.Fatalf("liveness body = %q, want it to contain \"alive\"", rec.Body.String())
	}
}

func TestHandleReady(t *testing.T) {
	okCheck := checker{name: "ok-dep", check: func(context.Context) error { return nil }}
	badCheck := checker{name: "bad-dep", check: func(context.Context) error { return errors.New("boom") }}

	tests := []struct {
		name       string
		checkers   []checker
		wantStatus int
		wantBody   string
	}{
		{
			name:       "all healthy",
			checkers:   []checker{okCheck},
			wantStatus: http.StatusOK,
			wantBody:   `"ready"`,
		},
		{
			name:       "one unhealthy fails readiness",
			checkers:   []checker{okCheck, badCheck},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `"not_ready"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if err := handleReady(tt.checkers)(c); err != nil {
				t.Fatalf("handleReady returned error: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("readiness status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("readiness body = %q, want it to contain %s", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

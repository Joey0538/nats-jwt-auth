package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

type authRequest struct {
	SSOToken      string `json:"sso_token"`
	NATSPublicKey string `json:"nats_public_key"`
}

type authResponse struct {
	UserInfo *userInfoResp `json:"user"`
	NATSJwt  string        `json:"nats_jwt"`
}

type userInfoResp struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

// handleAuth validates an SSO token and issues a NATS user JWT, recording the
// auth business metrics along the way.
func (a *app) handleAuth(c echo.Context) error {
	ctx := c.Request().Context()

	var req authRequest
	if err := c.Bind(&req); err != nil {
		a.recordAuthFailure(ctx, "bad_request", "")
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	result, err := a.auth.Authenticate(ctx, req.SSOToken, req.NATSPublicKey)
	if err != nil {
		a.recordAuthFailure(ctx, reasonFor(err), validationResultFor(err))
		return mapAuthError(err)
	}

	a.recordAuthSuccess(ctx)
	return c.JSON(http.StatusOK, authResponse{
		NATSJwt: result.NATSJWT,
		UserInfo: &userInfoResp{
			Subject:           result.User.Subject,
			Email:             result.User.Email,
			Name:              result.User.Name,
			PreferredUsername: result.User.PreferredUsername,
			GivenName:         result.User.GivenName,
			FamilyName:        result.User.FamilyName,
		},
	})
}

// recordAuthSuccess increments the success-path counters: a valid token was
// validated, authentication succeeded, and a NATS JWT was issued.
func (a *app) recordAuthSuccess(ctx context.Context) {
	a.metrics.authentications.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", "success"),
	))
	a.metrics.tokenValidation.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", "valid"),
	))
	a.metrics.tokensIssued.Add(ctx, 1)
}

// recordAuthFailure increments the failure-path counters. validationResult is
// empty for failures that occur before/around token validation (e.g. a
// malformed request), in which case the token-validation counter is skipped.
func (a *app) recordAuthFailure(ctx context.Context, reason, validationResult string) {
	a.metrics.authentications.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", "failure"),
		attribute.String("reason", reason),
	))
	if validationResult != "" {
		a.metrics.tokenValidation.Add(ctx, 1, metric.WithAttributes(
			attribute.String("result", validationResult),
		))
	}
}

// reasonFor maps a typed authentication error to a low-cardinality reason
// label for the auth_authentication_total counter.
func reasonFor(err error) string {
	switch {
	case errors.Is(err, natsauth.ErrMissingToken),
		errors.Is(err, natsauth.ErrMissingNKey),
		errors.Is(err, natsauth.ErrInvalidNKey):
		return "bad_request"
	case errors.Is(err, natsauth.ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, natsauth.ErrInvalidToken):
		return "invalid_token"
	case errors.Is(err, natsauth.ErrAccessDenied):
		return "access_denied"
	default:
		return "internal"
	}
}

// validationResultFor maps a typed error to a token-validation result label,
// or "" when the error is not about token validation.
func validationResultFor(err error) string {
	switch {
	case errors.Is(err, natsauth.ErrTokenExpired):
		return "expired"
	case errors.Is(err, natsauth.ErrInvalidToken):
		return "invalid"
	default:
		return ""
	}
}

// mapAuthError translates typed authenticator errors into HTTP responses.
func mapAuthError(err error) *echo.HTTPError {
	switch {
	case errors.Is(err, natsauth.ErrMissingToken),
		errors.Is(err, natsauth.ErrMissingNKey),
		errors.Is(err, natsauth.ErrInvalidNKey):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, natsauth.ErrTokenExpired):
		return echo.NewHTTPError(http.StatusUnauthorized, "SSO token has expired, please re-login")
	case errors.Is(err, natsauth.ErrInvalidToken):
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid SSO token")
	case errors.Is(err, natsauth.ErrAccessDenied):
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, "internal server error")
	}
}

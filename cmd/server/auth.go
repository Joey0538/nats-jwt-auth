package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

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

// handleAuth validates an SSO (TSSO) token and issues a NATS user JWT, recording
// the business metrics along the way.
func (a *app) handleAuth(c echo.Context) error {
	ctx := c.Request().Context()

	var req authRequest
	if err := c.Bind(&req); err != nil {
		a.metrics.recordAuthentication(ctx, "tsso", "failure")
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	result, err := a.auth.Authenticate(ctx, req.SSOToken, req.NATSPublicKey)
	if err != nil {
		a.recordAuthFailure(ctx, err)
		return mapAuthError(err)
	}

	// Success: TSSO token was valid, authentication succeeded, NATS JWT issued.
	a.metrics.recordTokenValidation(ctx, "valid")
	a.metrics.recordAuthentication(ctx, "tsso", "success")
	a.metrics.recordTokenIssued(ctx, "nats")

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

// recordAuthFailure records the failure-path business metrics. Token-validation
// outcomes are only recorded when validation was actually attempted (i.e. a
// token was present and parsed), so malformed requests don't skew the
// valid/invalid/expired distribution.
func (a *app) recordAuthFailure(ctx context.Context, err error) {
	a.metrics.recordAuthentication(ctx, "tsso", "failure")

	switch {
	case errors.Is(err, natsauth.ErrTokenExpired):
		a.metrics.recordTokenValidation(ctx, "expired")
	case errors.Is(err, natsauth.ErrInvalidToken):
		a.metrics.recordTokenValidation(ctx, "invalid")
	case errors.Is(err, natsauth.ErrAccessDenied):
		// Token validated successfully; the failure is authorization, not validation.
		a.metrics.recordTokenValidation(ctx, "valid")
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

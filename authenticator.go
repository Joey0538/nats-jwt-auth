package natsauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/nats-io/nkeys"

	internaljwt "github.com/joey0538/nats-jwt-auth/internal/jwt"
	internaloidc "github.com/joey0538/nats-jwt-auth/internal/oidc"
)

// Authenticator is the framework-agnostic core of the NATS auth package.
// It validates SSO tokens, resolves permissions, and signs NATS JWTs.
//
// Use this directly when you want to integrate with your own HTTP framework
// (Gin, Chi, net/http, etc.) and control the request/response format.
//
// For a batteries-included Echo server, use the echoserver package instead.
//
// Usage:
//
//	auth, err := natsauth.NewAuthenticator(ctx, cfg,
//	    natsauth.WithPermissionsProvider(myProvider),
//	)
//	// In your HTTP handler:
//	result, err := auth.Authenticate(ctx, ssoToken, natsPublicKey)
type Authenticator struct {
	validator   *internaloidc.Validator
	signer      *internaljwt.Signer
	permissions PermissionsProvider
	logger      *slog.Logger // nil means use slog.Default()
}

// AuthResult is returned by Authenticate on success. Teams use this to
// build their own HTTP response in whatever format they need.
type AuthResult struct {
	// User holds the validated identity from the SSO token.
	User *UserClaims

	// NATSJWT is the signed NATS user JWT. Pass this to the client
	// so it can connect to NATS with it.
	NATSJWT string
}

// Option configures an Authenticator (and by extension, a Server).
type Option func(*Authenticator)

// WithPermissionsProvider lets teams plug in their own logic for
// determining what NATS subjects each user can access.
//
// If not provided, DefaultPermissionsProvider is used.
func WithPermissionsProvider(p PermissionsProvider) Option {
	return func(a *Authenticator) {
		a.permissions = p
	}
}

// WithLogger overrides the default logger (slog.Default).
// Use this when you want library logs to go somewhere different
// from your application's default logger (e.g. a separate auth audit log).
func WithLogger(l *slog.Logger) Option {
	return func(a *Authenticator) {
		a.logger = l
	}
}

// log returns the configured logger, falling back to slog.Default().
func (a *Authenticator) log() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.Default()
}

// NewAuthenticator creates the framework-agnostic authenticator.
// It connects to the OIDC provider at startup — fails fast if unreachable.
//
// Usage:
//
//	auth, err := natsauth.NewAuthenticator(ctx, natsauth.Config{
//	    OIDCIssuerURL:   "https://sso.company.com/realms/my-realm",
//	    OIDCAudience:    "my-chat-app",
//	    NATSAccountSeed: "SA...",
//	    NATSJWTExpiry:   time.Hour,
//	}, natsauth.WithPermissionsProvider(myProvider))
func NewAuthenticator(ctx context.Context, cfg Config, opts ...Option) (*Authenticator, error) {
	cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	a := &Authenticator{
		permissions: DefaultPermissionsProvider{},
	}

	for _, opt := range opts {
		opt(a)
	}

	validator, err := internaloidc.NewValidator(ctx, internaloidc.ValidatorConfig{
		IssuerURL:        cfg.OIDCIssuerURL,
		Audience:         cfg.OIDCAudience,
		TLSSkipVerify:    cfg.TLSSkipVerify,
		DiscoveryTimeout: cfg.OIDCDiscoveryTimeout,
	})
	if err != nil {
		return nil, err
	}
	a.validator = validator

	signer, err := internaljwt.NewSigner(cfg.NATSAccountSeed, cfg.NATSJWTExpiry)
	if err != nil {
		return nil, err
	}
	a.signer = signer

	return a, nil
}

// Authenticate validates the SSO token, resolves permissions, and signs a
// NATS JWT. This is the core method teams call from their HTTP handlers.
//
// Returns typed errors that callers can map to HTTP status codes:
//
//	errors.Is(err, ErrMissingToken)    → 400
//	errors.Is(err, ErrMissingNKey)     → 400
//	errors.Is(err, ErrInvalidNKey)     → 400
//	errors.Is(err, ErrTokenExpired)    → 401
//	errors.Is(err, ErrInvalidToken)    → 401
//	errors.Is(err, ErrAccessDenied)    → 403
//	errors.Is(err, ErrSigningFailed)   → 500
//	errors.Is(err, ErrPermissionLookup)→ 500
func (a *Authenticator) Authenticate(ctx context.Context, ssoToken, natsPublicKey string) (*AuthResult, error) {
	if ssoToken == "" {
		return nil, ErrMissingToken
	}
	if natsPublicKey == "" {
		return nil, ErrMissingNKey
	}
	if !nkeys.IsValidPublicUserKey(natsPublicKey) {
		return nil, ErrInvalidNKey
	}

	// Validate SSO token
	oidcClaims, err := a.validator.Validate(ctx, ssoToken)
	if err != nil {
		if errors.Is(err, internaloidc.ErrTokenExpired) {
			a.log().Warn("SSO token expired", "error", err)
			return nil, ErrTokenExpired
		}
		a.log().Error("OIDC validation failed", "error", err)
		return nil, ErrInvalidToken
	}

	userClaims := &UserClaims{
		Subject:           oidcClaims.Subject,
		Email:             oidcClaims.Email,
		Name:              oidcClaims.Name,
		PreferredUsername: oidcClaims.PreferredUsername,
		GivenName:         oidcClaims.GivenName,
		FamilyName:        oidcClaims.FamilyName,
		Extra:             oidcClaims.Extra,
	}

	// Resolve permissions
	perms, err := a.permissions.GetPermissions(ctx, userClaims)
	if err != nil {
		if errors.Is(err, ErrAccessDenied) {
			a.log().Warn("access denied", "error", err, "subject", userClaims.Subject)
			return nil, err
		}
		a.log().Error("permissions lookup failed", "error", err, "subject", userClaims.Subject)
		return nil, fmt.Errorf("%w: %w", ErrPermissionLookup, err)
	}

	// Sign NATS JWT
	natsJWT, err := a.signer.Sign(natsPublicKey, userClaims.Subject, internaljwt.UserPermissions{
		PubAllow: perms.PubAllow,
		SubAllow: perms.SubAllow,
		PubDeny:  perms.PubDeny,
		SubDeny:  perms.SubDeny,
	})
	if err != nil {
		a.log().Error("JWT signing failed", "error", err)
		return nil, fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}

	return &AuthResult{
		User:    userClaims,
		NATSJWT: natsJWT,
	}, nil
}

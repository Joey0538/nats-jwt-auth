package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims holds the validated identity extracted from an OIDC token.
type Claims struct {
	Extra             map[string]interface{}
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	GivenName         string
	FamilyName        string
}

// ErrTokenExpired is returned when the SSO token has passed its expiry time.
var ErrTokenExpired = fmt.Errorf("oidc: token has expired")

// ValidatorConfig controls how the OIDC validator behaves.
type ValidatorConfig struct {
	IssuerURL     string
	Audience      string
	TLSSkipVerify bool

	// DiscoveryTimeout is the maximum time allowed for OIDC issuer discovery
	// and HTTP requests to the JWKS endpoint. Must be set by the caller.
	DiscoveryTimeout time.Duration
}

// Validator verifies OIDC tokens against an issuer's JWKS endpoint.
type Validator struct {
	verifier   *oidc.IDTokenVerifier
	httpClient *http.Client
	audience   string
}

// NewValidator connects to the OIDC issuer at startup and fetches its
// JWKS keys. Fails fast if the issuer is unreachable.
func NewValidator(ctx context.Context, cfg ValidatorConfig) (*Validator, error) {
	timeout := cfg.DiscoveryTimeout

	var httpClient *http.Client

	if cfg.TLSSkipVerify {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // intentional for dev environments
			},
		}
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	// Ensure issuer discovery cannot hang indefinitely.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to connect to issuer %q: %w", cfg.IssuerURL, err)
	}

	oidcConfig := &oidc.Config{
		ClientID: cfg.Audience,
	}

	verifier := provider.Verifier(oidcConfig)

	return &Validator{
		verifier:   verifier,
		httpClient: httpClient,
		audience:   cfg.Audience,
	}, nil
}

// Validate verifies the raw OIDC token string and extracts user claims.
// Returns ErrTokenExpired if the token's exp claim is in the past.
func (v *Validator) Validate(ctx context.Context, rawToken string) (Claims, error) {
	// Re-attach the custom HTTP client so JWKS fetches also use TLSSkipVerify.
	if v.httpClient != nil {
		ctx = oidc.ClientContext(ctx, v.httpClient)
	}

	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		var expErr *oidc.TokenExpiredError
		if errors.As(err, &expErr) {
			return Claims{}, ErrTokenExpired
		}
		return Claims{}, fmt.Errorf("oidc: token verification failed: %w", err)
	}

	var tokenClaims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
	}

	if err := idToken.Claims(&tokenClaims); err != nil {
		return Claims{}, fmt.Errorf("oidc: failed to parse token claims: %w", err)
	}

	// Parse all claims into Extra for teams that need custom fields
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err != nil {
		return Claims{}, fmt.Errorf("oidc: failed to parse extra claims: %w", err)
	}
	// Remove standard fields so Extra only has the extras
	for _, key := range []string{
		"sub", "email", "name", "preferred_username",
		"given_name", "family_name",
		"iss", "aud", "exp", "iat", "nbf", "jti",
		"azp", "typ", "sid", "at_hash", "email_verified",
	} {
		delete(allClaims, key)
	}

	return Claims{
		Subject:           idToken.Subject,
		Email:             tokenClaims.Email,
		Name:              tokenClaims.Name,
		PreferredUsername: tokenClaims.PreferredUsername,
		GivenName:         tokenClaims.GivenName,
		FamilyName:        tokenClaims.FamilyName,
		Extra:             allClaims,
	}, nil
}

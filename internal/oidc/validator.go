package oidc

import (
	"context"
	"fmt"
	"strings"
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

// Validator verifies OIDC tokens against an issuer's JWKS endpoint.
type Validator struct {
	verifier *oidc.IDTokenVerifier
}

// NewValidator connects to the OIDC issuer at startup and fetches its
// JWKS keys. Fails fast if the issuer is unreachable.
func NewValidator(ctx context.Context, issuerURL, audience string) (*Validator, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to connect to issuer %q: %w", issuerURL, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: audience,
	})

	return &Validator{verifier: verifier}, nil
}

// Validate verifies the raw OIDC token string and extracts user claims.
// Returns ErrTokenExpired if the token's exp claim is in the past.
func (v *Validator) Validate(ctx context.Context, rawToken string) (Claims, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		if isExpiredError(err) {
			return Claims{}, ErrTokenExpired
		}
		return Claims{}, fmt.Errorf("oidc: token verification failed: %w", err)
	}

	// Double-check expiry explicitly (belt + suspenders)
	if idToken.Expiry.Before(time.Now()) {
		return Claims{}, ErrTokenExpired
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

func isExpiredError(err error) bool {
	// go-oidc returns "oidc: token is expired" when exp is in the past
	return strings.Contains(err.Error(), "expired")
}

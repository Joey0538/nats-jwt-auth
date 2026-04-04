package natsauth

import (
	"fmt"
	"time"
)

// Config holds everything a team needs to provide to run their own
// instance of the NATS auth service.
//
// Zero values for optional fields use sensible defaults (applied
// internally by NewAuthenticator):
//
//	Port                 → "8080"
//	NATSJWTExpiry        → 1h
//	OIDCDiscoveryTimeout → 10s
type Config struct {
	// Port the HTTP server listens on. Only used by echoserver.Server.
	// Zero value defaults to "8080".
	Port string

	// OIDCIssuerURL is your company SSO discovery URL (required).
	OIDCIssuerURL string

	// OIDCAudience is the client_id your app is registered as in SSO (required).
	OIDCAudience string

	// NATSAccountSeed is the SA... private seed for YOUR team's NATS account (required).
	NATSAccountSeed string

	// NATSJWTExpiry controls how long issued JWTs are valid.
	// Zero value defaults to 1 hour.
	NATSJWTExpiry time.Duration

	// TLSSkipVerify disables TLS cert verification for the OIDC issuer. Dev only.
	TLSSkipVerify bool

	// OIDCDiscoveryTimeout is the maximum time allowed for OIDC issuer discovery.
	// Zero value defaults to 10s.
	OIDCDiscoveryTimeout time.Duration
}

func (c *Config) withDefaults() {
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.NATSJWTExpiry == 0 {
		c.NATSJWTExpiry = time.Hour
	}
	if c.OIDCDiscoveryTimeout == 0 {
		c.OIDCDiscoveryTimeout = 10 * time.Second
	}
}

func (c *Config) validate() error {
	if c.OIDCIssuerURL == "" {
		return fmt.Errorf("natsauth: OIDCIssuerURL is required")
	}
	if c.OIDCAudience == "" {
		return fmt.Errorf("natsauth: OIDCAudience is required")
	}
	if c.NATSAccountSeed == "" {
		return fmt.Errorf("natsauth: NATSAccountSeed is required")
	}
	return nil
}

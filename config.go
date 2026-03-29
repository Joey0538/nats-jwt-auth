package natsauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds everything a team needs to provide to run their own
// instance of the NATS auth service. Each team has their own values here.
type Config struct {
	// Port the HTTP server listens on. Default: 8080
	Port string `mapstructure:"port"`

	// OIDCIssuerURL is your company SSO discovery URL.
	// Keycloak example: https://sso.company.com/realms/your-realm
	// Okta example:     https://your-org.okta.com/oauth2/default
	OIDCIssuerURL string `mapstructure:"oidc_issuer_url"`

	// OIDCAudience is the client_id your app is registered as in SSO.
	OIDCAudience string `mapstructure:"oidc_audience"`

	// NATSAccountSeed is the SA... private seed for YOUR team's NATS account.
	// Get this from your NATS infra team. Starts with "SA".
	// Each team gets their own — it only signs JWTs for your team's account.
	NATSAccountSeed string `mapstructure:"nats_account_seed"`

	// NATSJWTExpiry controls how long issued JWTs are valid.
	// NATS will drop the client connection when this expires.
	// Default: 1 hour. Accepts Go duration strings: "1h", "30m", "2h30m".
	NATSJWTExpiry time.Duration `mapstructure:"nats_jwt_expiry"`
}

// LoadConfig reads configuration from environment variables and optionally
// from .env / config files. Env vars like OIDC_ISSUER_URL map directly to
// Config fields via mapstructure tags.
//
// Search paths for config files (optional, env vars always take precedence):
//   - ./.env
//   - /etc/nats-auth/.env
//
// Usage:
//
//	cfg, err := natsauth.LoadConfig()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	srv, err := natsauth.NewServer(ctx, cfg)
func LoadConfig() (Config, error) {
	v := viper.New()

	// Env vars: OIDC_ISSUER_URL, OIDC_AUDIENCE, NATS_ACCOUNT_SEED, etc.
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind all config keys to their env var names so Unmarshal picks them up.
	// AutomaticEnv only works with Get(), not Unmarshal — BindEnv fixes that.
	for _, key := range []string{
		"port",
		"oidc_issuer_url",
		"oidc_audience",
		"nats_account_seed",
		"nats_jwt_expiry",
	} {
		_ = v.BindEnv(key) //nolint:errcheck // BindEnv only fails with zero args
	}

	// Also read from .env / config file if present
	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/nats-auth/")
	_ = v.ReadInConfig() //nolint:errcheck // optional — env vars take precedence

	// Defaults
	v.SetDefault("port", "8080")
	v.SetDefault("nats_jwt_expiry", "1h")

	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(
		mapstructureDurationHook(),
	)); err != nil {
		return Config{}, fmt.Errorf("natsauth: failed to unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) withDefaults() {
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.NATSJWTExpiry == 0 {
		c.NATSJWTExpiry = time.Hour
	}
}

func (c *Config) validate() error {
	if c.OIDCIssuerURL == "" {
		return fmt.Errorf("natsauth: OIDCIssuerURL is required (env: OIDC_ISSUER_URL)")
	}
	if c.OIDCAudience == "" {
		return fmt.Errorf("natsauth: OIDCAudience is required (env: OIDC_AUDIENCE)")
	}
	if c.NATSAccountSeed == "" {
		return fmt.Errorf("natsauth: NATSAccountSeed is required (env: NATS_ACCOUNT_SEED)")
	}
	return nil
}

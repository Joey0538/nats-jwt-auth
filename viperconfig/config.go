// Package viperconfig reads natsauth.Config from environment variables and
// optional .env files using Viper. Import this only if you want automatic
// config loading — otherwise build natsauth.Config directly.
package viperconfig

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

// LoadConfig reads configuration from environment variables and optionally
// from .env / config files. Env vars map to Config fields:
//
//	OIDC_ISSUER_URL   → OIDCIssuerURL
//	OIDC_AUDIENCE     → OIDCAudience
//	NATS_ACCOUNT_SEED → NATSAccountSeed
//	NATS_JWT_EXPIRY   → NATSJWTExpiry (e.g. "1h", "30m")
//	TLS_SKIP_VERIFY   → TLSSkipVerify
//	PORT              → Port
//
// Search paths for config files (optional, env vars always take precedence):
//   - ./.env
//   - /etc/nats-auth/.env
func LoadConfig() (natsauth.Config, error) {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	for _, key := range []string{
		"port",
		"oidc_issuer_url",
		"oidc_audience",
		"nats_account_seed",
		"nats_jwt_expiry",
		"tls_skip_verify",
		"oidc_discovery_timeout",
	} {
		_ = v.BindEnv(key) //nolint:errcheck // BindEnv only fails with zero args
	}

	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/nats-auth/")
	_ = v.ReadInConfig() //nolint:errcheck // optional

	v.SetDefault("port", "8080")
	v.SetDefault("nats_jwt_expiry", "1h")

	// Intermediate struct with mapstructure tags for Viper unmarshalling.
	var raw struct {
		Port                 string        `mapstructure:"port"`
		OIDCIssuerURL        string        `mapstructure:"oidc_issuer_url"`
		OIDCAudience         string        `mapstructure:"oidc_audience"`
		NATSAccountSeed      string        `mapstructure:"nats_account_seed"`
		NATSJWTExpiry        time.Duration `mapstructure:"nats_jwt_expiry"`
		TLSSkipVerify        bool          `mapstructure:"tls_skip_verify"`
		OIDCDiscoveryTimeout time.Duration `mapstructure:"oidc_discovery_timeout"`
	}

	if err := v.Unmarshal(&raw, viper.DecodeHook(durationHook())); err != nil {
		return natsauth.Config{}, fmt.Errorf("viperconfig: failed to unmarshal: %w", err)
	}

	return natsauth.Config{
		Port:                 raw.Port,
		OIDCIssuerURL:        raw.OIDCIssuerURL,
		OIDCAudience:         raw.OIDCAudience,
		NATSAccountSeed:      raw.NATSAccountSeed,
		NATSJWTExpiry:        raw.NATSJWTExpiry,
		TLSSkipVerify:        raw.TLSSkipVerify,
		OIDCDiscoveryTimeout: raw.OIDCDiscoveryTimeout,
	}, nil
}

// durationHook lets Viper decode "1h", "30m" strings into time.Duration.
func durationHook() mapstructure.DecodeHookFuncType {
	return func(_ reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return time.ParseDuration(v)
		case int64:
			return time.Duration(v), nil
		default:
			return data, nil
		}
	}
}

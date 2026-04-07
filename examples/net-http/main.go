// Example: using Authenticator with net/http — no framework dependency.
//
// This shows how a team can use the natsauth package without Echo (or any
// framework). You control the request parsing, response format, and HTTP
// status code mapping entirely.
//
// Run:
//
//	OIDC_ISSUER_URL=http://localhost:9090/realms/chatapp \
//	OIDC_AUDIENCE=nats-chat \
//	NATS_ACCOUNT_SEED=SA... \
//	go run ./examples/net-http
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	natsauth "github.com/joey0538/nats-jwt-auth"
)

func main() {
	cfg := natsauth.Config{
		OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
		OIDCAudience:    os.Getenv("OIDC_AUDIENCE"),
		NATSAccountSeed: os.Getenv("NATS_ACCOUNT_SEED"),
		TLSSkipVerify:   os.Getenv("TLS_SKIP_VERIFY") == "true",
	}

	auth, err := natsauth.NewAuthenticator(context.Background(), cfg,
		natsauth.WithPermissionsProvider(
			natsauth.PermissionsProviderFunc(func(_ context.Context, user *natsauth.UserClaims) (natsauth.Permissions, error) {
				rooms := []string{"room.general", fmt.Sprintf("user.%s.>", user.Subject)}
				return natsauth.Permissions{PubAllow: rooms, SubAllow: rooms}, nil
			}),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Wire up your own HTTP handlers with whatever response format you want.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth", handleAuth(auth))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// -----------------------------------------------------------------------
// Your team's custom request/response types — design them however you want.
// -----------------------------------------------------------------------

type myAuthRequest struct {
	SSOToken string `json:"token"`
	NATSNKey string `json:"nkey"`
}

type myAuthResponse struct {
	JWT      string `json:"jwt"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type errorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func handleAuth(auth *natsauth.Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req myAuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		result, err := auth.Authenticate(r.Context(), req.SSOToken, req.NATSNKey)
		if err != nil {
			status, msg := mapError(err)
			writeError(w, status, msg)
			return
		}

		// Your custom response — include only the fields your frontend needs.
		json.NewEncoder(w).Encode(myAuthResponse{
			JWT:      result.NATSJWT,
			Username: result.User.PreferredUsername,
			Email:    result.User.Email,
		})
	}
}

// mapError converts Authenticate errors to HTTP status codes.
// Teams control this mapping entirely.
func mapError(err error) (int, string) {
	switch {
	case errors.Is(err, natsauth.ErrMissingToken),
		errors.Is(err, natsauth.ErrMissingNKey),
		errors.Is(err, natsauth.ErrInvalidNKey):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, natsauth.ErrTokenExpired):
		return http.StatusUnauthorized, "token expired, please re-login"
	case errors.Is(err, natsauth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid SSO token"
	case errors.Is(err, natsauth.ErrAccessDenied):
		return http.StatusForbidden, err.Error()
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(errorResponse{Code: code, Message: msg})
}

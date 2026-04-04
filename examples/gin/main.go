// Example: using Authenticator with Gin — custom response format.
//
// Shows how a team using Gin (not Echo) can integrate natsauth.
// The response format is entirely different from the built-in Server's format.
//
// Run:
//
//	OIDC_ISSUER_URL=http://localhost:9090/realms/chatapp \
//	OIDC_AUDIENCE=nats-chat \
//	NATS_ACCOUNT_SEED=SA... \
//	go run ./examples/gin
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

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
			natsauth.PermissionsProviderFunc(func(_ context.Context, user natsauth.UserClaims) (natsauth.Permissions, error) {
				rooms := []string{"room.general", fmt.Sprintf("user.%s.>", user.Subject)}
				return natsauth.Permissions{PubAllow: rooms, SubAllow: rooms}, nil
			}),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.POST("/api/v1/nats/token", handleNATSToken(auth))
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	log.Fatal(r.Run(":8080"))
}

// -----------------------------------------------------------------------
// Team's custom response — completely different shape from the built-in.
// Maybe your frontend expects camelCase, or you want to nest things differently.
// -----------------------------------------------------------------------

type tokenResponse struct {
	Data tokenData `json:"data"`
}

type tokenData struct {
	NATSToken string    `json:"natsToken"`
	User      tokenUser `json:"user"`
}

type tokenUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}

func handleNATSToken(auth *natsauth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			SSOToken  string `json:"ssoToken"  binding:"required"`
			PublicKey string `json:"publicKey" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing ssoToken or publicKey"})
			return
		}

		result, err := auth.Authenticate(c.Request.Context(), req.SSOToken, req.PublicKey)
		if err != nil {
			status, msg := mapHTTPStatus(err)
			c.JSON(status, gin.H{"error": msg})
			return
		}

		c.JSON(http.StatusOK, tokenResponse{
			Data: tokenData{
				NATSToken: result.NATSJWT,
				User: tokenUser{
					ID:       result.User.Subject,
					Username: result.User.PreferredUsername,
					Email:    result.User.Email,
					FullName: result.User.Name,
				},
			},
		})
	}
}

func mapHTTPStatus(err error) (int, string) {
	switch {
	case errors.Is(err, natsauth.ErrMissingToken),
		errors.Is(err, natsauth.ErrMissingNKey),
		errors.Is(err, natsauth.ErrInvalidNKey):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, natsauth.ErrTokenExpired):
		return http.StatusUnauthorized, "SSO token has expired, please re-login"
	case errors.Is(err, natsauth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid SSO token"
	case errors.Is(err, natsauth.ErrAccessDenied):
		return http.StatusForbidden, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

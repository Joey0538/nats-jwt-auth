package jwt

import (
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Signer creates NATS user JWTs signed by the account's private key.
type Signer struct {
	accountKP     nkeys.KeyPair
	accountPubKey string
	expiry        time.Duration
}

// NewSigner creates a signer from the account's SA... seed string.
func NewSigner(accountSeed string, expiry time.Duration) (*Signer, error) {
	kp, err := nkeys.FromSeed([]byte(accountSeed))
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid account seed: %w", err)
	}

	pubKey, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to extract public key from seed: %w", err)
	}

	// Verify this is actually an account key (starts with "A")
	if !nkeys.IsValidPublicAccountKey(pubKey) {
		return nil, fmt.Errorf("jwt: seed is not an account key (public key %s does not start with A)", pubKey)
	}

	return &Signer{
		accountKP:     kp,
		accountPubKey: pubKey,
		expiry:        expiry,
	}, nil
}

// UserPermissions mirrors the permission model from the public API.
type UserPermissions struct {
	PubAllow []string
	SubAllow []string
	PubDeny  []string
	SubDeny  []string
}

// Sign creates a NATS user JWT bound to the given user public key.
// The JWT is signed by the account key and includes the specified permissions.
//
// The caller (Authenticator.Authenticate) is responsible for validating the
// user public key before calling Sign.
func (s *Signer) Sign(userPubKey string, userID string, perms UserPermissions) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = userID
	claims.IssuerAccount = s.accountPubKey
	claims.Expires = time.Now().Add(s.expiry).Unix()

	// Set permissions
	claims.Pub.Allow.Add(perms.PubAllow...)
	claims.Sub.Allow.Add(perms.SubAllow...)
	if len(perms.PubDeny) > 0 {
		claims.Pub.Deny.Add(perms.PubDeny...)
	}
	if len(perms.SubDeny) > 0 {
		claims.Sub.Deny.Add(perms.SubDeny...)
	}

	token, err := claims.Encode(s.accountKP)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to encode user JWT: %w", err)
	}

	return token, nil
}

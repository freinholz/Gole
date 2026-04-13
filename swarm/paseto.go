package swarm

// PASETO v4.public implementation using Ed25519.
//
// Token format: "v4.public." + base64url(message || signature)
//
// Security properties:
//   - Tokens are signed by the controller's Ed25519 key and cannot be forged.
//   - Each token binds an EndpointID to a specific Ed25519 public key,
//     domain, group, and role/flags. An endpoint cannot claim another's ID.
//   - Tokens expire and must be refreshed.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const pasetoHeader = "v4.public."

// TokenClaims is the payload embedded in a PASETO v4.public token.
type TokenClaims struct {
	EndpointID  EndpointID `json:"eid"`
	Domain      DomainID   `json:"dom"`
	Group       GroupID    `json:"grp"`
	RoleFlags   uint8      `json:"rf"`
	PublicKey   []byte     `json:"pk"`            // Ed25519 public key of the endpoint
	Fingerprint string     `json:"fp,omitempty"`  // machine+local_id fingerprint (audit)
	IssuedAt    time.Time  `json:"iat"`
	ExpiresAt   time.Time  `json:"exp"`
	Issuer      string     `json:"iss"`
}

// le64 encodes an integer as 64-bit unsigned little-endian per PASETO spec.
func le64(n int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(n))
	return b
}

// pae implements Pre-Authentication Encoding (PAE) per the PASETO specification.
func pae(pieces ...[]byte) []byte {
	output := le64(len(pieces))
	for _, p := range pieces {
		output = append(output, le64(len(p))...)
		output = append(output, p...)
	}
	return output
}

// SignToken creates a PASETO v4.public token signed with an Ed25519 private key.
func SignToken(claims *TokenClaims, secretKey ed25519.PrivateKey) (string, error) {
	message, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	m2 := pae([]byte(pasetoHeader), message, []byte{}, []byte{})
	signature := ed25519.Sign(secretKey, m2)

	payload := make([]byte, len(message)+ed25519.SignatureSize)
	copy(payload, message)
	copy(payload[len(message):], signature)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return pasetoHeader + encoded, nil
}

// VerifyToken verifies a PASETO v4.public token and returns the claims.
func VerifyToken(token string, publicKey ed25519.PublicKey) (*TokenClaims, error) {
	if !strings.HasPrefix(token, pasetoHeader) {
		return nil, errors.New("invalid token: wrong header")
	}

	encoded := token[len(pasetoHeader):]
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid token: bad encoding: %w", err)
	}

	if len(payload) < ed25519.SignatureSize {
		return nil, errors.New("invalid token: too short")
	}

	message := payload[:len(payload)-ed25519.SignatureSize]
	signature := payload[len(payload)-ed25519.SignatureSize:]

	m2 := pae([]byte(pasetoHeader), message, []byte{}, []byte{})
	if !ed25519.Verify(publicKey, m2, signature) {
		return nil, errors.New("invalid token: signature verification failed")
	}

	var claims TokenClaims
	if err := json.Unmarshal(message, &claims); err != nil {
		return nil, fmt.Errorf("invalid token: bad claims: %w", err)
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("invalid token: expired")
	}

	return &claims, nil
}

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

type Key [KeySize]byte

var (
	ErrInvalidKeySize = errors.New("invalid key size: must be exactly 32 bytes")
)

// GeneratePrivateKey generates a secure random 32-byte X25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return Key{}, fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	// Clamp private key according to RFC 7748
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// PublicKey computes the corresponding X25519 public key from a private key.
func (k Key) PublicKey() (Key, error) {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, fmt.Errorf("failed to derive public key: %w", err)
	}
	var out Key
	copy(out[:], pub)
	return out, nil
}

// String encodes the key as a base64 string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseKey decodes a base64-encoded string into a 32-byte Key.
func ParseKey(s string) (Key, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("failed to decode base64 key: %w", err)
	}
	if len(decoded) != KeySize {
		return Key{}, fmt.Errorf("%w (got %d bytes)", ErrInvalidKeySize, len(decoded))
	}
	var k Key
	copy(k[:], decoded)
	return k, nil
}

package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateAndDerivePublicKey(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey derivation failed: %v", err)
	}

	if bytes.Equal(priv[:], pub[:]) {
		t.Fatal("private key and public key must not be equal")
	}

	// Verify base64 string round-trip
	pubStr := pub.String()
	parsedPub, err := ParseKey(pubStr)
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}

	if !bytes.Equal(pub[:], parsedPub[:]) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestParseInvalidKey(t *testing.T) {
	_, err := ParseKey("not-valid-base64!@#$")
	if err == nil {
		t.Fatal("expected error on invalid base64, got nil")
	}

	// Valid base64, but wrong length (16 bytes instead of 32)
	shortB64 := "YWJjZGVmZ2hpamtsbW5vcA=="
	_, err = ParseKey(shortB64)
	if err == nil {
		t.Fatal("expected error on short key length, got nil")
	}
}

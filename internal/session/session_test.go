package session

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSecureSessionRoundtrip(t *testing.T) {
	keyA := make([]byte, chacha20poly1305.KeySize)
	keyB := make([]byte, chacha20poly1305.KeySize)
	rand.Read(keyA)
	rand.Read(keyB)

	sessionID := uint32(0x98765432)

	// Alice sends with keyA, receives with keyB
	alice, err := NewSecureSession(sessionID, keyA, keyB)
	if err != nil {
		t.Fatalf("failed to create alice session: %v", err)
	}

	// Bob sends with keyB, receives with keyA
	bob, err := NewSecureSession(sessionID, keyB, keyA)
	if err != nil {
		t.Fatalf("failed to create bob session: %v", err)
	}

	// 1. Alice encrypts payload to Bob
	originalPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	frame, err := alice.Encrypt(originalPayload)
	if err != nil {
		t.Fatalf("alice encrypt failed: %v", err)
	}

	// 2. Bob decrypts frame from Alice
	decrypted, err := bob.Decrypt(frame)
	if err != nil {
		t.Fatalf("bob decrypt failed: %v", err)
	}

	if !bytes.Equal(originalPayload, decrypted) {
		t.Fatalf("decrypted payload %q != original %q", decrypted, originalPayload)
	}

	// 3. Replay attack: Bob receives the same frame again!
	_, err = bob.Decrypt(frame)
	if err == nil {
		t.Fatal("expected replay attack error on re-transmitted frame, got nil")
	}

	// 4. Tamper attack: Bob receives a tampered frame (bit flipped in ciphertext)
	frame2, err := alice.Encrypt([]byte("another packet"))
	if err != nil {
		t.Fatalf("alice encrypt 2 failed: %v", err)
	}

	tamperedFrame := make([]byte, len(frame2))
	copy(tamperedFrame, frame2)
	tamperedFrame[len(tamperedFrame)-1] ^= 0x01 // Flip last bit

	_, err = bob.Decrypt(tamperedFrame)
	if err == nil {
		t.Fatal("expected authentication failure on tampered frame, got nil")
	}
}

func TestSessionIDMismatch(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	session1, _ := NewSecureSession(100, key, key)
	session2, _ := NewSecureSession(200, key, key)

	frame, _ := session1.Encrypt([]byte("test"))
	_, err := session2.Decrypt(frame)
	if err == nil {
		t.Fatal("expected session ID mismatch error, got nil")
	}
}

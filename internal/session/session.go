package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/vikrannntttt8/Dark_Tunnel/internal/contracts"
	"github.com/vikrannntttt8/Dark_Tunnel/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrSessionExpired    = errors.New("session counter overflow or lifetime expired")
	ErrReplayDetected    = errors.New("packet counter rejected by replay window (replayed or too old)")
	ErrAuthFailed        = errors.New("ciphertext authentication failed")
	ErrSessionIDMismatch = errors.New("packet receiver session ID does not match local session ID")
)

// Default session limits per WireGuard / PRD recommendations
const (
	DefaultRekeyAfterTime  = 2 * time.Minute
	DefaultRekeyAfterBytes = 1 * 1024 * 1024 * 1024 // 1 GiB
)

// SecureSession implements contracts.Session using ChaCha20-Poly1305 and sliding-window replay protection.
type SecureSession struct {
	sessionID    uint32
	sendAEAD     cipher.AEAD
	recvAEAD     cipher.AEAD
	sendCounter  atomic.Uint64
	bytesSent    atomic.Uint64
	bytesRecv    atomic.Uint64
	replayWindow *ReplayWindow
	createdAt    time.Time
	maxLifetime  time.Duration
	maxBytes     uint64
}

// Verify that SecureSession satisfies the contracts.Session interface at compile time.
var _ contracts.Session = (*SecureSession)(nil)

// NewSecureSession creates a new bidirectional AEAD transport session.
// sendKey and recvKey must be exactly 32 bytes (derived from the Noise handshake).
func NewSecureSession(sessionID uint32, sendKey []byte, recvKey []byte) (*SecureSession, error) {
	if len(sendKey) != chacha20poly1305.KeySize || len(recvKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: keys must be %d bytes", chacha20poly1305.KeySize)
	}

	sendAEAD, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create send AEAD cipher: %w", err)
	}

	recvAEAD, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create recv AEAD cipher: %w", err)
	}

	return &SecureSession{
		sessionID:    sessionID,
		sendAEAD:     sendAEAD,
		recvAEAD:     recvAEAD,
		replayWindow: NewReplayWindow(),
		createdAt:    time.Now(),
		maxLifetime:  DefaultRekeyAfterTime,
		maxBytes:     DefaultRekeyAfterBytes,
	}, nil
}

// Encrypt encrypts a raw IP packet and frames it into a wire transport message.
func (s *SecureSession) Encrypt(plaintext []byte) ([]byte, error) {
	// Increment monotonic 64-bit counter
	counter := s.sendCounter.Add(1)
	if counter == math.MaxUint64 {
		return nil, ErrSessionExpired
	}

	// Construct 12-byte nonce: 4 bytes zero + 8 bytes counter (little-endian RFC 7539 / WireGuard format)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)

	// Encrypt plaintext with ChaCha20-Poly1305
	ciphertext := s.sendAEAD.Seal(nil, nonce[:], plaintext, nil)

	// Encode wire frame
	frame := make([]byte, protocol.HeaderSizeTransport+len(ciphertext))
	n, err := protocol.EncodeTransport(frame, s.sessionID, counter, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to encode transport frame: %w", err)
	}

	s.bytesSent.Add(uint64(n))
	return frame[:n], nil
}

// Decrypt authenticates, verifies replay window, and decrypts a wire transport message.
func (s *SecureSession) Decrypt(frame []byte) ([]byte, error) {
	msg, err := protocol.DecodeTransport(frame)
	if err != nil {
		return nil, err
	}

	// Verify session destination
	if msg.ReceiverIndex != s.sessionID {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrSessionIDMismatch, s.sessionID, msg.ReceiverIndex)
	}

	// Verify against sliding window replay protection
	if !s.replayWindow.ValidateAndMark(msg.Counter) {
		return nil, fmt.Errorf("%w: counter %d", ErrReplayDetected, msg.Counter)
	}

	// Construct nonce matching sender's counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], msg.Counter)

	// Authenticate and decrypt
	plaintext, err := s.recvAEAD.Open(nil, nonce[:], msg.Ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}

	s.bytesRecv.Add(uint64(len(frame)))
	return plaintext, nil
}

// SessionID returns the unique identifier for this session.
func (s *SecureSession) SessionID() uint32 {
	return s.sessionID
}

// IsExpired returns true if rekeying is required.
func (s *SecureSession) IsExpired() bool {
	if s.sendCounter.Load() >= math.MaxUint64-1000 {
		return true
	}
	if time.Since(s.createdAt) > s.maxLifetime {
		return true
	}
	if s.bytesSent.Load() > s.maxBytes {
		return true
	}
	return false
}

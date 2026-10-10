package contracts

import (
	"context"
	"net"
)

// TunDevice is owned by Person A (Network & Systems).
// It abstracts the virtual network adapter (Linux /dev/net/tun, Windows Wintun, macOS utun).
type TunDevice interface {
	// ReadPacket reads a single raw IPv4/IPv6 packet from the OS kernel.
	// The buffer returned or populated contains the IP header + payload.
	ReadPacket() ([]byte, error)

	// WritePacket injects a raw IPv4/IPv6 packet into the OS kernel stack.
	WritePacket(p []byte) error

	// MTU returns the Maximum Transmission Unit configured on the TUN interface.
	MTU() int

	// Close terminates the TUN device adapter and cleans up OS handles.
	Close() error
}

// NetConfigurator is owned by Person A (Network & Systems).
// It manages OS routing tables, DNS overrides, and NAT/firewall rules.
type NetConfigurator interface {
	// Apply applies the network configuration (assigns IP, updates routing table, sets DNS).
	Apply() error

	// Revert cleanly restores original routing tables and DNS settings.
	// It MUST be idempotent (safe to call multiple times or during crashes/cleanups).
	Revert() error
}

// Session is owned by Person B (Protocol & App).
// It abstracts symmetric AEAD encryption, decryption, counters, and replay protection.
type Session interface {
	// Encrypt wraps a raw plaintext IP packet into an authenticated AEAD transport frame.
	Encrypt(plaintext []byte) (frame []byte, err error)

	// Decrypt authenticates, verifies replay window, and decrypts an AEAD transport frame.
	Decrypt(frame []byte) (plaintext []byte, err error)

	// SessionID returns the identifier associated with this session.
	SessionID() uint32

	// IsExpired returns true if the session exceeds max lifetime or byte quota (triggering rekey).
	IsExpired() bool
}

// Handshaker is owned by Person B (Protocol & App).
// It manages the mutual-authenticated Noise handshake exchange.
type Handshaker interface {
	// InitiateHandshake begins a client-side handshake to the specified remote server.
	InitiateHandshake(ctx context.Context, serverStaticPub [32]byte, conn net.Conn) (Session, error)

	// AcceptHandshake processes an incoming handshake initiation from a client.
	AcceptHandshake(ctx context.Context, packet []byte, senderAddr net.Addr) (Session, []byte, error)
}

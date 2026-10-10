package contracts

import (
	"errors"
	"sync"
	"sync/atomic"
)

// MockTunDevice provides an in-memory channel-backed TunDevice.
// Owned by B for testing crypto & session loops without needing root privileges or TUN drivers.
type MockTunDevice struct {
	Inbound  chan []byte
	Outbound chan []byte
	closed   atomic.Bool
	mtu      int
}

// NewMockTunDevice creates a MockTunDevice with a default MTU of 1420.
func NewMockTunDevice(bufferSize int, mtu int) *MockTunDevice {
	if mtu <= 0 {
		mtu = 1420
	}
	return &MockTunDevice{
		Inbound:  make(chan []byte, bufferSize),
		Outbound: make(chan []byte, bufferSize),
		mtu:      mtu,
	}
}

func (m *MockTunDevice) ReadPacket() ([]byte, error) {
	if m.closed.Load() {
		return nil, errors.New("tun device closed")
	}
	pkt, ok := <-m.Inbound
	if !ok {
		return nil, errors.New("tun device closed")
	}
	return pkt, nil
}

func (m *MockTunDevice) WritePacket(p []byte) error {
	if m.closed.Load() {
		return errors.New("tun device closed")
	}
	// Copy buffer to prevent race conditions
	cp := make([]byte, len(p))
	copy(cp, p)
	m.Outbound <- cp
	return nil
}

func (m *MockTunDevice) MTU() int {
	return m.mtu
}

func (m *MockTunDevice) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.Inbound)
		close(m.Outbound)
	}
	return nil
}

// MockSession provides a plaintext passthrough Session.
// Used by Person A in Milestone M2 to test raw packet loops and routing without encryption.
type MockSession struct {
	sessionID uint32
	mu        sync.RWMutex
	expired   bool
}

// NewMockSession creates a plaintext passthrough session.
func NewMockSession(id uint32) *MockSession {
	return &MockSession{
		sessionID: id,
	}
}

func (m *MockSession) Encrypt(plaintext []byte) ([]byte, error) {
	// Plaintext frame: simply copies bytes
	frame := make([]byte, len(plaintext))
	copy(frame, plaintext)
	return frame, nil
}

func (m *MockSession) Decrypt(frame []byte) ([]byte, error) {
	// Plaintext frame: simply returns the payload
	plaintext := make([]byte, len(frame))
	copy(plaintext, frame)
	return plaintext, nil
}

func (m *MockSession) SessionID() uint32 {
	return m.sessionID
}

func (m *MockSession) IsExpired() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.expired
}

func (m *MockSession) SetExpired(expired bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expired = expired
}

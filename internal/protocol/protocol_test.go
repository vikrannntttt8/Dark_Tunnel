package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeTransport(t *testing.T) {
	receiverIndex := uint32(0x12345678)
	counter := uint64(0x0102030405060708)
	ciphertext := []byte("encrypted_ip_packet_sample_data_with_mac_tag_16")

	buf := make([]byte, 1024)
	n, err := EncodeTransport(buf, receiverIndex, counter, ciphertext)
	if err != nil {
		t.Fatalf("unexpected encode error: %v", err)
	}

	raw := buf[:n]
	msg, err := DecodeTransport(raw)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if msg.ReceiverIndex != receiverIndex {
		t.Errorf("expected receiver index 0x%x, got 0x%x", receiverIndex, msg.ReceiverIndex)
	}
	if msg.Counter != counter {
		t.Errorf("expected counter 0x%x, got 0x%x", counter, msg.Counter)
	}
	if !bytes.Equal(msg.Ciphertext, ciphertext) {
		t.Errorf("expected ciphertext %q, got %q", ciphertext, msg.Ciphertext)
	}
}

func TestDecodeTransportTooShort(t *testing.T) {
	shortData := []byte{TypeTransportData, 0x01, 0x02}
	_, err := DecodeTransport(shortData)
	if err == nil {
		t.Fatal("expected error for truncated packet, got nil")
	}
}

func TestDecodeTransportInvalidType(t *testing.T) {
	buf := make([]byte, MinTransportSize)
	buf[0] = 0xFF // Invalid type
	_, err := DecodeTransport(buf)
	if err == nil {
		t.Fatal("expected error for invalid message type, got nil")
	}
}



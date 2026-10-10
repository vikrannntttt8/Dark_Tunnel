//go:build fuzz

package protocol

import (
	"testing"
)

func FuzzDecodeTransport(f *testing.F) {
	// Seed initial valid packet
	buf := make([]byte, 1024)
	n, _ := EncodeTransport(buf, 1, 1, []byte("fuzz_seed_payload_16_bytes_long"))
	f.Add(buf[:n])
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x03, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Verify parser never panics on arbitrary malformed inputs
		_, _ = DecodeTransport(data)
		_, _ = ParseMessageType(data)
	})
}

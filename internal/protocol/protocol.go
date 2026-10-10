package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire message type constants
const (
	TypeHandshakeInitiation byte = 0x01
	TypeHandshakeResponse   byte = 0x02
	TypeTransportData       byte = 0x03
	TypeKeepalive           byte = 0x04
)

// Header & message sizes
const (
	HeaderSizeTransport = 13 // 1 byte Type + 4 bytes ReceiverSessionID + 8 bytes Counter
	Poly1305TagSize     = 16 // AEAD authentication tag
	MinTransportSize    = HeaderSizeTransport + Poly1305TagSize
)

var (
	ErrPacketTooShort    = errors.New("packet is shorter than minimum message size")
	ErrInvalidMsgType    = errors.New("unrecognized message type")
	ErrBufferTooSmall    = errors.New("target buffer too small for encoding")
	ErrPayloadTooLarge   = errors.New("payload exceeds maximum allowed datagram size")
)

// TransportMessage represents an encrypted data frame or keepalive frame.
type TransportMessage struct {
	ReceiverIndex uint32
	Counter       uint64
	Ciphertext    []byte // Includes ChaCha20 ciphertext + 16-byte Poly1305 tag
}

// EncodeTransport writes a TransportMessage into a byte slice.
func EncodeTransport(dst []byte, receiverIndex uint32, counter uint64, ciphertext []byte) (int, error) {
	needed := HeaderSizeTransport + len(ciphertext)
	if len(dst) < needed {
		return 0, ErrBufferTooSmall
	}

	dst[0] = TypeTransportData
	binary.LittleEndian.PutUint32(dst[1:5], receiverIndex)
	binary.LittleEndian.PutUint64(dst[5:13], counter)
	copy(dst[13:], ciphertext)

	return needed, nil
}

// DecodeTransport parses a transport message from raw wire bytes.
func DecodeTransport(src []byte) (*TransportMessage, error) {
	if len(src) < MinTransportSize {
		return nil, ErrPacketTooShort
	}

	if src[0] != TypeTransportData && src[0] != TypeKeepalive {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidMsgType, src[0])
	}

	receiverIndex := binary.LittleEndian.Uint32(src[1:5])
	counter := binary.LittleEndian.Uint64(src[5:13])
	ciphertext := src[13:]

	return &TransportMessage{
		ReceiverIndex: receiverIndex,
		Counter:       counter,
		Ciphertext:    ciphertext,
	}, nil
}

// ParseMessageType inspects the first byte of a packet to determine its type without full decoding.
func ParseMessageType(src []byte) (byte, error) {
	if len(src) == 0 {
		return 0, ErrPacketTooShort
	}
	t := src[0]
	if t < TypeHandshakeInitiation || t > TypeKeepalive {
		return 0, fmt.Errorf("%w: 0x%02x", ErrInvalidMsgType, t)
	}
	return t, nil
}

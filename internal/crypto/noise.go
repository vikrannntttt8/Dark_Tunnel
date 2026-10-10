package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

var (
	ErrHandshakeFailed     = errors.New("noise handshake negotiation failed")
	ErrUnauthorizedPeer    = errors.New("remote peer static public key not authorized")
	ErrInvalidMessageOrder = errors.New("noise message received out of expected handshake sequence")
)

// CipherSuite configuration: Noise_IK_25519_ChaChaPoly_BLAKE2s
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// TransportKeys holds the symmetric cipher states for bidirectionally encrypted communication.
type TransportKeys struct {
	SendCipher *noise.CipherState
	RecvCipher *noise.CipherState
	PeerStatic Key
}

// ClientHandshakeState manages the initiator side of the Noise IK handshake.
type ClientHandshakeState struct {
	hs         *noise.HandshakeState
	localPriv  Key
	localPub   Key
	remotePub  Key
	localIndex uint32
}

// NewClientHandshake creates a new initiator handshake state.
func NewClientHandshake(localPriv Key, remoteServerPub Key) (*ClientHandshakeState, error) {
	localPub, err := localPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	config := noise.Config{
		CipherSuite: cipherSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: localPriv[:],
			Public:  localPub[:],
		},
		PeerStatic: remoteServerPub[:],
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Noise client state: %w", err)
	}

	var indexBytes [4]byte
	_, _ = rand.Read(indexBytes[:])
	localIndex := binary.LittleEndian.Uint32(indexBytes[:])

	return &ClientHandshakeState{
		hs:         hs,
		localPriv:  localPriv,
		localPub:   localPub,
		remotePub:  remoteServerPub,
		localIndex: localIndex,
	}, nil
}

// CreateInitiation creates the 1st handshake message (Type 0x01) to send to the server.
func (c *ClientHandshakeState) CreateInitiation(payload []byte) ([]byte, error) {
	// Prepend 1-byte message type and 4-byte local sender index
	header := make([]byte, 5)
	header[0] = 0x01 // TypeHandshakeInitiation
	binary.LittleEndian.PutUint32(header[1:5], c.localIndex)

	noiseMsg, _, _, err := c.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to write Noise initiation message: %w", err)
	}

	return append(header, noiseMsg...), nil
}

// ProcessResponse processes the 2nd handshake message (Type 0x02) from the server.
// Returns the negotiated symmetric transport cipher states.
func (c *ClientHandshakeState) ProcessResponse(resp []byte) (*TransportKeys, error) {
	if len(resp) < 9 { // 1 byte Type + 4 bytes sender index + 4 bytes receiver index
		return nil, errors.New("handshake response message too short")
	}

	if resp[0] != 0x02 {
		return nil, fmt.Errorf("expected handshake response (0x02), got 0x%02x", resp[0])
	}

	// Verify receiver index matches our localIndex
	receiverIndex := binary.LittleEndian.Uint32(resp[5:9])
	if receiverIndex != c.localIndex {
		return nil, fmt.Errorf("receiver index mismatch: expected %d, got %d", c.localIndex, receiverIndex)
	}

	noiseMsg := resp[9:]
	_, sendCipher, recvCipher, err := c.hs.ReadMessage(nil, noiseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to process Noise response message: %w", err)
	}

	if sendCipher == nil || recvCipher == nil {
		return nil, ErrHandshakeFailed
	}

	return &TransportKeys{
		SendCipher: sendCipher,
		RecvCipher: recvCipher,
		PeerStatic: c.remotePub,
	}, nil
}

// ServerHandshakeState manages the responder side of the Noise IK handshake.
type ServerHandshakeState struct {
	hs           *noise.HandshakeState
	serverPriv   Key
	serverPub    Key
	clientIndex  uint32
	serverIndex  uint32
	isAuthorized func(clientPub Key) bool
}

// NewServerHandshake creates a new responder handshake state.
func NewServerHandshake(serverPriv Key, isAuthorized func(clientPub Key) bool) (*ServerHandshakeState, error) {
	serverPub, err := serverPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive server public key: %w", err)
	}

	config := noise.Config{
		CipherSuite: cipherSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: serverPriv[:],
			Public:  serverPub[:],
		},
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Noise server state: %w", err)
	}

	var indexBytes [4]byte
	_, _ = rand.Read(indexBytes[:])
	serverIndex := binary.LittleEndian.Uint32(indexBytes[:])

	return &ServerHandshakeState{
		hs:           hs,
		serverPriv:   serverPriv,
		serverPub:    serverPub,
		serverIndex:  serverIndex,
		isAuthorized: isAuthorized,
	}, nil
}

// ProcessInitiation processes an incoming 1st handshake message (Type 0x01).
// Returns the verified peer static public key and the response message to send back.
func (s *ServerHandshakeState) ProcessInitiation(initiation []byte, responsePayload []byte) (*TransportKeys, []byte, error) {
	if len(initiation) < 5 {
		return nil, nil, errors.New("handshake initiation too short")
	}

	if initiation[0] != 0x01 {
		return nil, nil, fmt.Errorf("expected handshake initiation (0x01), got 0x%02x", initiation[0])
	}

	s.clientIndex = binary.LittleEndian.Uint32(initiation[1:5])
	noiseMsg := initiation[5:]

	_, _, _, err := s.hs.ReadMessage(nil, noiseMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read Noise initiation message: %w", err)
	}

	// Extract and authorize the client's static public key
	peerStaticBytes := s.hs.PeerStatic()
	if len(peerStaticBytes) != KeySize {
		return nil, nil, errors.New("remote peer static key missing or invalid size")
	}

	var clientPub Key
	copy(clientPub[:], peerStaticBytes)

	if s.isAuthorized != nil && !s.isAuthorized(clientPub) {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnauthorizedPeer, clientPub.String())
	}

	// Create 2nd handshake message: [Type (1B)] + [ServerIndex (4B)] + [ClientIndex (4B)] + [NoiseMsg]
	header := make([]byte, 9)
	header[0] = 0x02
	binary.LittleEndian.PutUint32(header[1:5], s.serverIndex)
	binary.LittleEndian.PutUint32(header[5:9], s.clientIndex)

	noiseResp, recvCipher, sendCipher, err := s.hs.WriteMessage(nil, responsePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write Noise response message: %w", err)
	}

	respMsg := append(header, noiseResp...)

	keys := &TransportKeys{
		SendCipher: sendCipher,
		RecvCipher: recvCipher,
		PeerStatic: clientPub,
	}

	return keys, respMsg, nil
}

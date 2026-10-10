package crypto

import (
	"bytes"
	"testing"
)

func TestNoiseIKHandshakeSuccess(t *testing.T) {
	// 1. Generate keys for Client and Server
	clientPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPub, _ := clientPriv.PublicKey()

	serverPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverPub, _ := serverPriv.PublicKey()

	// 2. Initialize handshake states
	clientState, err := NewClientHandshake(clientPriv, serverPub)
	if err != nil {
		t.Fatalf("failed to init client handshake: %v", err)
	}

	serverState, err := NewServerHandshake(serverPriv, func(peerPub Key) bool {
		return bytes.Equal(peerPub[:], clientPub[:])
	})
	if err != nil {
		t.Fatalf("failed to init server handshake: %v", err)
	}

	// 3. Client creates Handshake Initiation (Message 1)
	initMsg, err := clientState.CreateInitiation([]byte("client_hello_payload"))
	if err != nil {
		t.Fatalf("failed to create initiation: %v", err)
	}

	// 4. Server processes Initiation and generates Handshake Response (Message 2)
	serverKeys, respMsg, err := serverState.ProcessInitiation(initMsg, []byte("server_response_payload"))
	if err != nil {
		t.Fatalf("server failed to process initiation: %v", err)
	}

	if !bytes.Equal(serverKeys.PeerStatic[:], clientPub[:]) {
		t.Fatal("server did not authenticate client public key correctly")
	}

	// 5. Client processes Response
	clientKeys, err := clientState.ProcessResponse(respMsg)
	if err != nil {
		t.Fatalf("client failed to process response: %v", err)
	}

	// 6. Test that Client SendCipher encrypts and Server RecvCipher decrypts!
	testPlaintext := []byte("secret_wire_packet_test")
	ciphertext, err := clientKeys.SendCipher.Encrypt(nil, nil, testPlaintext)
	if err != nil {
		t.Fatalf("client encryption failed: %v", err)
	}

	decrypted, err := serverKeys.RecvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("server decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, testPlaintext) {
		t.Fatalf("expected decrypted text %q, got %q", testPlaintext, decrypted)
	}

	// 7. Test reverse direction: Server SendCipher encrypts and Client RecvCipher decrypts!
	replyPlaintext := []byte("server_reply_ip_packet")
	replyCiphertext, err := serverKeys.SendCipher.Encrypt(nil, nil, replyPlaintext)
	if err != nil {
		t.Fatalf("server encryption failed: %v", err)
	}

	clientDecrypted, err := clientKeys.RecvCipher.Decrypt(nil, nil, replyCiphertext)
	if err != nil {
		t.Fatalf("client decryption failed: %v", err)
	}

	if !bytes.Equal(clientDecrypted, replyPlaintext) {
		t.Fatalf("expected client decrypted text %q, got %q", replyPlaintext, clientDecrypted)
	}
}

func TestNoiseIKHandshakeUnauthorizedPeer(t *testing.T) {
	clientPriv, _ := GeneratePrivateKey()
	serverPriv, _ := GeneratePrivateKey()
	serverPub, _ := serverPriv.PublicKey()

	clientState, _ := NewClientHandshake(clientPriv, serverPub)

	// Server that denies this client
	serverState, _ := NewServerHandshake(serverPriv, func(peerPub Key) bool {
		return false // Unauthorized
	})

	initMsg, err := clientState.CreateInitiation(nil)
	if err != nil {
		t.Fatalf("failed to create initiation: %v", err)
	}

	_, _, err = serverState.ProcessInitiation(initMsg, nil)
	if err == nil {
		t.Fatal("expected error for unauthorized peer, got nil")
	}
}

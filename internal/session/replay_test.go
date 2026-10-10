package session

import (
	"testing"
)

func TestReplayWindowInOrder(t *testing.T) {
	rw := NewReplayWindow()

	for i := uint64(1); i <= 1000; i++ {
		if !rw.ValidateAndMark(i) {
			t.Fatalf("expected packet %d to be accepted", i)
		}
	}
}

func TestReplayWindowDuplicates(t *testing.T) {
	rw := NewReplayWindow()

	if !rw.ValidateAndMark(1) {
		t.Fatal("expected seq 1 to be accepted")
	}
	if rw.ValidateAndMark(1) {
		t.Fatal("expected duplicate seq 1 to be rejected")
	}

	rw.ValidateAndMark(2)
	rw.ValidateAndMark(3)
	if rw.ValidateAndMark(2) {
		t.Fatal("expected duplicate seq 2 to be rejected")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	rw := NewReplayWindow()

	// Receive packet 10
	if !rw.ValidateAndMark(10) {
		t.Fatal("expected seq 10 to be accepted")
	}

	// Receive older packets out of order
	if !rw.ValidateAndMark(5) {
		t.Fatal("expected seq 5 to be accepted")
	}
	if !rw.ValidateAndMark(8) {
		t.Fatal("expected seq 8 to be accepted")
	}

	// Duplicate of out-of-order packet
	if rw.ValidateAndMark(5) {
		t.Fatal("expected duplicate seq 5 to be rejected")
	}
}

func TestReplayWindowPastBoundary(t *testing.T) {
	rw := NewReplayWindow()

	// Send packet 3000
	rw.ValidateAndMark(3000)

	// Packet 500 is > 2048 packets behind 3000, must be rejected
	if rw.ValidateAndMark(500) {
		t.Fatal("expected seq 500 to be rejected as outside window")
	}

	// Packet 2000 is 1000 behind 3000, within window, should be accepted
	if !rw.ValidateAndMark(2000) {
		t.Fatal("expected seq 2000 to be accepted")
	}

	// But duplicate must be rejected
	if rw.ValidateAndMark(2000) {
		t.Fatal("expected duplicate seq 2000 to be rejected")
	}
}

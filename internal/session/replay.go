package session

import (
	"sync"
)

const (
	// WindowSize is the size of the replay window in bits (packets).
	// 2048 packets allows out-of-order packets up to 2048 packets behind the latest.
	WindowSize = 2048
	wordBits   = 64
	numWords   = WindowSize / wordBits // 32 words
)

// ReplayWindow tracks received counter nonces to protect against replay attacks.
// Thread-safe and allocation-free.
type ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap [numWords]uint64
}

// NewReplayWindow creates an empty replay window.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// ValidateAndMark checks if seq is acceptable and marks it as received.
// Returns true if packet is accepted, false if it is a duplicate or too old.
func (rw *ReplayWindow) ValidateAndMark(seq uint64) bool {
	if seq == 0 {
		return false
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Initial packet received
	if rw.maxSeq == 0 {
		rw.maxSeq = seq
		rw.bitmap[0] = 1
		return true
	}

	// Case 1: Packet is newer than the highest counter seen so far
	if seq > rw.maxSeq {
		diff := seq - rw.maxSeq
		if diff >= WindowSize {
			// Jumped ahead past entire window; clear bitmap
			for i := range rw.bitmap {
				rw.bitmap[i] = 0
			}
			rw.bitmap[0] = 1
		} else {
			// Slide the window by diff bits
			rw.shiftLeft(diff)
			rw.bitmap[0] |= 1
		}
		rw.maxSeq = seq
		return true
	}

	// Case 2: Packet is older than or equal to highest counter seen
	diff := rw.maxSeq - seq
	if diff >= WindowSize {
		// Packet is too old (outside window)
		return false
	}

	wordIndex := diff / wordBits
	bitIndex := diff % wordBits

	// Check if already received
	if (rw.bitmap[wordIndex] & (1 << bitIndex)) != 0 {
		// Duplicate / replayed packet!
		return false
	}

	// Mark as received
	rw.bitmap[wordIndex] |= (1 << bitIndex)
	return true
}

// shiftLeft shifts the window bitmap by n positions
func (rw *ReplayWindow) shiftLeft(n uint64) {
	if n >= WindowSize {
		for i := range rw.bitmap {
			rw.bitmap[i] = 0
		}
		return
	}

	wordShift := int(n / wordBits)
	bitShift := n % wordBits

	// Shift words
	if wordShift > 0 {
		for i := numWords - 1; i >= wordShift; i-- {
			rw.bitmap[i] = rw.bitmap[i-wordShift]
		}
		for i := 0; i < wordShift; i++ {
			rw.bitmap[i] = 0
		}
	}

	// Shift bits across word boundaries
	if bitShift > 0 {
		var carry uint64
		for i := 0; i < numWords; i++ {
			newCarry := rw.bitmap[i] >> (wordBits - bitShift)
			rw.bitmap[i] = (rw.bitmap[i] << bitShift) | carry
			carry = newCarry
		}
	}
}

// Reset clears the replay window state
func (rw *ReplayWindow) Reset() {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	rw.maxSeq = 0
	for i := range rw.bitmap {
		rw.bitmap[i] = 0
	}
}

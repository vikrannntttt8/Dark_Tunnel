# Dark Tunnel — Self-Learning & Architectural Decision Log

> **Role: Person B (Protocol & App)**  
> **Collaborator: Person A (Network & Systems)**  
> **Repository:** `https://github.com/vikrannntttt8/Dark_Tunnel.git`  
> **Purpose:** Document every change, architectural decision, underlying network/cryptographic principles, and how each component operates so that any team member or reviewer can thoroughly understand and defend the entire implementation.

---

## 1. Project Overview & System Philosophy

Dark Tunnel is a modern, educational, high-performance VPN implementation in Go inspired by the WireGuard design philosophy, using the Noise Protocol Framework for mutual authentication and modern AEAD encryption for wire protection.

### Two-Person Work Split
- **Person A (Network & Systems):** The OS-level "pipe" — Virtual network adapter (TUN), kernel routing tables, default routes, DNS overrides, host-routing to avoid tunnel loops, and Linux iptables/nftables NAT masquerading.
- **Person B (Protocol & App — Us):** The cryptographic "secret sauce" & operator interface — Static X25519 key management, Noise IK mutual authentication handshake, ChaCha20-Poly1305 transport encryption, monotonic counter nonces, sliding-window replay attack prevention, keepalive/rekey state machines, and the embedded client UI.

---

## 2. Milestone 0: Setup & Interface Contracts

### 2.1 Why Interface Contracts First?
In a two-person systems project, the greatest risk is **merge conflict and dependency blocking**:
- Person A cannot test TUN device loops without some packet handler.
- Person B cannot test cryptographic encryption loops without feeding raw packets.

**The Solution:**
We established `internal/contracts/contracts.go`. Both developers agree strictly on these Go interfaces:
1. `TunDevice`: Read and write raw IP packets to/from the operating system kernel.
2. `NetConfigurator`: Apply and cleanly revert routing tables, default routes, and DNS.
3. `Session`: Encrypt and decrypt packets using authenticated symmetric keys with replay checks.
4. `Handshaker`: Initiate and accept the Noise IK handshake to derive shared transport keys.

### 2.2 Independent Development via Mocks (`internal/contracts/mocks.go`)
- **`MockTunDevice`:** An in-memory, thread-safe channel implementation of `TunDevice`. Person B can simulate thousands of raw IP packets flowing through the crypto/session engine without needing root privileges, Windows Wintun drivers, or a Linux VM.
- **`MockSession`:** A zero-overhead plaintext passthrough implementation of `Session`. Person A can test TUN setup, OS routing table manipulation, NAT masquerading, and raw packet delivery (Milestone M2) before encryption is merged.

---

## 3. Cryptography & Protocol Architecture (Person B Deep-Dive)

### 3.1 The "Never Invent Homemade Crypto" Rule
Cryptographic design flaws almost always arise from improper nonce reuse, flawed handshakes, or missing authentication. Dark Tunnel relies strictly on vetted cryptographic standards:
- **Diffie-Hellman Key Exchange:** X25519 (`golang.org/x/crypto/curve25519`).
- **Authenticated Encryption:** ChaCha20-Poly1305 AEAD (`golang.org/x/crypto/chacha20poly1305`).
- **Handshake Framework:** Noise Protocol (`Noise_IK_25519_ChaChaPoly_BLAKE2s` via `github.com/flynn/noise`).
  - **`I` (Initiator static key is transmitted to responder during handshake):** The client identifies itself with its public key.
  - **`K` (Known):** The responder's static public key is pre-known to the initiator (like SSH `authorized_keys` or WireGuard configs).
  - Mutual authentication is achieved in **1 round-trip (2 messages)**.

### 3.2 Wire Protocol Message Format
Every datagram sent over UDP starts with a 1-byte message header:
| Type | Name | Wire Payload Structure |
|:---:|:---|:---|
| `0x01` | Handshake Initiation | `[Type (1B)] + [Sender Index (4B)] + [Noise Ephemeral PubKey (32B)] + [Encrypted Static Key + Tag (48B)] + [Encrypted Timestamp + Tag (28B)]` |
| `0x02` | Handshake Response | `[Type (1B)] + [Sender Index (4B)] + [Receiver Index (4B)] + [Noise Ephemeral PubKey (32B)] + [Empty AEAD Tag (16B)]` |
| `0x03` | Encrypted Transport Data | `[Type (1B)] + [Receiver Session ID (4B)] + [Counter / Nonce (8B)] + [ChaCha20-Poly1305 Ciphertext + 16B Poly1305 Tag]` |
| `0x04` | Keepalive | Encrypted Transport Data containing empty (0-byte) inner payload to maintain NAT state without passing data to TUN. |

### 3.3 Replay Protection (Sliding Window Algorithm)
- **The Threat:** An adversary on the public internet captures an encrypted packet and re-transmits it later (replay attack). Even if they cannot decrypt it, replayed packets could disrupt connections or exhaust resources.
- **The Solution:** A 64-bit monotonic packet counter combined with a bitmap sliding window (`2048` packets = 32 `uint64` words).
  1. If counter > highest received: slide the window forward and mark bit as received.
  2. If counter <= highest received, check if it falls within the window:
     - If already marked in the bitmap: **Drop packet silently** (duplicate/replay).
     - If not marked: mark bit and accept.
  3. If counter is older than the window capacity: **Drop packet silently**.

### 3.4 ChaCha20-Poly1305 AEAD & Nonce Management
- **Nonce Structure:** RFC 7539 specifies a 96-bit (12-byte) nonce. We use the WireGuard standard format: 4 bytes of `0x00` followed by the 64-bit little-endian counter.
- **Why Monotonic Counters:** ChaCha20 is a stream cipher. If the same key and nonce are EVER reused for two distinct plaintexts ($C_1 = P_1 \oplus K$, $C_2 = P_2 \oplus K$), an attacker can compute $C_1 \oplus C_2 = P_1 \oplus P_2$, completely exposing both plaintexts! By using an atomic 64-bit monotonic incrementer (`atomic.Uint64`), every transmitted frame is guaranteed a globally unique nonce.
- **Rekey Thresholds:** If the send counter approaches $2^{64}-1$, or the session exceeds 2 minutes or 1 GiB of traffic, the session is marked expired (`IsExpired() = true`) to trigger an ephemeral rekey.

---

## 4. Change Log & Step-by-Step Progress

| Date | Milestone / Component | Change Summary | Underlying Rationale |
|:---|:---|:---|:---|
| 2026-10-10 | M0 Setup | Created `.gitignore`, `Makefile`, `.github/workflows/ci.yml`, `go.mod` | Establishes reproducible build pipeline and automated CI testing. |
| 2026-10-10 | M0 Contracts | Defined `contracts.go` and `mocks.go` in `internal/contracts/` | Decouples Person A (Network) from Person B (Protocol) with clean Go interfaces. |
| 2026-10-10 | Documentation | Initialized `docs/PRD.md`, `docs/TEAM.md`, `docs/learning-notes.md` | Single source of truth for architecture and team collaboration. |
| 2026-10-10 | M3 Key Tool | Implemented `internal/crypto/keys.go` with X25519 key generation & RFC 7748 clamping | Provides cryptographic static key management and Base64 serialization. |
| 2026-10-10 | M3 Noise IK | Implemented `internal/crypto/noise.go` with 1-RTT mutual authentication | Mutual authentication using Noise IK pattern with Curve25519, ChaChaPoly, BLAKE2s. |
| 2026-10-10 | M4 Framing | Implemented `internal/protocol/protocol.go` with message parsing & fuzz tests | Wire-level serialization/deserialization with strict bounds checking. |
| 2026-10-10 | M4 Replay Window | Implemented `internal/session/replay.go` with 2048-bit bitmap sliding window | Constant-time duplicate and replay attack detection with zero memory allocation. |
| 2026-10-10 | M4 AEAD Transport | Implemented `internal/session/session.go` fulfilling `contracts.Session` | Encrypts raw IP packets with ChaCha20-Poly1305 and rejects replayed/tampered frames. |
| 2026-10-10 | CLI Tooling | Implemented `cmd/tunnel/main.go` supporting `genkey`, `pubkey`, `client`, `server` | Operator CLI for managing keypairs and bootstrapping services. |

---

## 5. Viva Defense / Interview Preparation

### Question 1: Why did we select Noise IK instead of TLS 1.3 for this VPN?
**Answer:**
TLS is designed for client-server web browsing with public key infrastructure (PKI, X.509 certificates, and certificate authorities). A VPN tunnel operates over raw UDP datagrams where peers typically pre-share static public keys (like WireGuard or SSH).
1. **Zero Certificate Overhead:** Noise IK relies directly on 32-byte raw Curve25519 public keys without multi-kilobyte certificate chains.
2. **Minimal Round Trips:** Noise IK establishes mutual authentication and transport keys in just **1 round-trip (2 messages)**.
3. **Identity Hiding:** The initiator's static public key is encrypted under the responder's known static key, preventing passive eavesdroppers from identifying which client is connecting.

### Question 2: How does the sliding window replay protection work, and why not just store a set of seen sequence numbers?
**Answer:**
Storing a hash set or list of seen sequence numbers would cause **unbounded memory consumption**. Over a multi-gigabyte session, millions of sequence numbers would exhaust RAM (or trigger Garbage Collection latency).
Instead, we use a fixed 2048-bit bitmap (32 `uint64` words = only 256 bytes total memory):
- As sequence numbers advance, the window shifts via bitwise shifts (`shiftLeft`).
- Recent packets within the window are tracked as single bits (0 = not seen, 1 = seen).
- Any packet older than the window width (2048 packets behind the highest counter) is dropped.
- Any packet whose bit is already 1 is dropped as a duplicate/replay.
- This provides constant memory $O(1)$, zero heap allocations, and nanosecond verification.

### Question 3: What happens if an adversary alters even a single bit of an encrypted packet in transit?
**Answer:**
ChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD) cipher. It computes a 16-byte Poly1305 MAC tag over the ciphertext and nonce.
When `session.Decrypt` calls `recvAEAD.Open`, the receiver recalculates the Poly1305 tag. If even 1 bit of the ciphertext or header was modified, authentication fails immediately (`ErrAuthFailed`). The packet is silently dropped without exposing plaintext or responding to the attacker.

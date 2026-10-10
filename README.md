# Dark Tunnel — High-Performance VPN From Scratch

[![CI](https://github.com/vikrannntttt8/Dark_Tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/vikrannntttt8/Dark_Tunnel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An educational, high-performance virtual private network (VPN) client and server built from scratch in **Go**. Inspired by the WireGuard architecture, Dark Tunnel provides secure, full-device IP tunneling with mutual authentication, zero-knowledge confidentiality, and a sleek user experience.

> **Disclaimer:** This project is an educational reimplementation of modern VPN concepts inspired by WireGuard. Cryptography uses vetted libraries (`golang.org/x/crypto`, `github.com/flynn/noise`). It is not yet audited for production-critical or adversarial nation-state environments.

---

## 👥 Two-Person Team Architecture

| Role | Focus | Owned Folders |
|---|---|---|
| **Person A: Network & Systems** | Virtual adapter (TUN), OS routes, DNS, NAT masquerading, cloud VM deployment | `internal/tun/`, `internal/netcfg/`, `internal/server/`, `scripts/`, `test/` |
| **Person B: Protocol & App** | X25519 keys, Noise IK handshake, ChaCha20-Poly1305 AEAD, replay windows, client UI | `internal/crypto/`, `internal/protocol/`, `internal/session/`, `internal/client/`, `internal/ui/`, `configs/` |
| **Shared** | Core interfaces, packet loops, CLI commands, documentation | `internal/contracts/`, `internal/tunnel/`, `cmd/tunnel/`, `docs/` |

---

## 🚀 Key Features

- **Mutual Authentication via Noise IK:** Single round-trip cryptographic handshake using Curve25519, ChaCha20-Poly1305, and BLAKE2s.
- **Symmetric Wire Encryption:** ChaCha20-Poly1305 AEAD with 64-bit monotonic counters per transmission direction.
- **Sliding-Window Replay Protection:** Rejects replayed and tampered packets with a zero-allocation bitmap window.
- **Clean OS Routing & Host-Route Protection:** Automatically prevents recursive routing loops by anchoring the VPN gateway route.
- **Built-in Key Generator:** Generate static Curve25519 keypairs directly via CLI.
- **Embedded Web UI:** Real-time metrics, connection status, latency, and transfer stats.

---

## 📐 System Architecture

```
┌────────────── CLIENT DEVICE ───────────────┐          ┌────────────── SERVER (Linux) ───────────────┐
│ Apps ─► OS routing table                   │          │                                             │
│           │ (default route → tun0)         │          │  UDP :51820  ◄── encrypted datagrams        │
│           ▼                                │          │      │                                      │
│     Virtual adapter (TUN)                  │          │      ▼                                      │
│           │ raw IP packets                 │          │  Session lookup (by session ID)             │
│           ▼                                │  UDP     │      │ decrypt + replay check               │
│  Tunnel engine: frame → AEAD encrypt ──────┼─────────►│      ▼                                      │
│           ▲                                │          │  Server TUN (10.7.0.1) ─► Kernel forwards   │
│           │ decrypt ◄──────────────────────┼◄─────────┤      ▲                  + NAT (masquerade)  │
│  Control: handshake, keepalive, rekey      │          │      │                        │             │
│  UI: Connect / status / stats              │          │      └────── replies ◄────────┴──► Internet │
└────────────────────────────────────────────┘          └─────────────────────────────────────────────┘
```

---

## 🛠️ CLI Quickstart

### 1. Build the Binary
```bash
go build -o bin/tunnel ./cmd/tunnel
```

### 2. Generate Keypairs
```bash
# Generate private key
./bin/tunnel genkey > private.key

# Derive public key from private key
./bin/tunnel pubkey < private.key > public.key
```

### 3. Start Server (Linux)
```bash
sudo ./bin/tunnel server -config configs/server.yaml
```

### 4. Start Client
```bash
sudo ./bin/tunnel client -config configs/client.yaml
```

---

## 📚 Documentation
- [PRD (Product Requirements Document)](docs/PRD.md)
- [Team Work Split & Guidelines](docs/TEAM.md)
- [Self-Learning & Implementation Log](docs/learning-notes.md)

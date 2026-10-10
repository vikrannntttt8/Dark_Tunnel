# PRD: "Tunnel" — A VPN App Built From Scratch

> **Supersedes v1 and v2.** Goal: a real VPN application (own client app, own server, own protocol design) that routes all of a device's traffic through a server you run.
>
> **Using this with Antigravity:** save as `docs/PRD.md`. First message to the agent: *"Read docs/PRD.md fully. Do NOT write code yet. Produce an implementation plan for Milestone 0 only and wait for my approval."* One milestone at a time. Prompts are in Section 13.

---

## 1. Vision & Goals

**Vision:** One small, cross-platform app where you press **Connect** and all your device's internet traffic travels through an encrypted tunnel to your own server.

| # | Goal | Measure |
|---|------|---------|
| G1 | Working full-device VPN | After Connect, `curl ifconfig.me` shows the server's IP with **no proxy settings** |
| G2 | Original architecture and code | Client, server, wire protocol and app UI are designed and written in this repo |
| G3 | Portfolio-grade | Clean repo, diagram, protocol spec, tests, demo video |
| G4 | Deep learning | Owner can explain TUN devices, encapsulation, handshake, NAT, MTU, routing |
| G5 | $0 cost | Free-tier server, open-source tooling |

**Non-goals:** commercial service, many users, payments, anonymity claims, bypassing laws or restrictions, multi-hop, mobile apps (v1).

---

## 2. The One Rule About "From Scratch"

"From scratch" here means **you build the VPN application and protocol design**. It does **not** mean inventing cryptographic primitives or a key-exchange from zero. Homemade crypto is how VPN projects become insecure.

| Built by you (the project) | Taken from vetted libraries (not reinvented) |
|----------------------------|----------------------------------------------|
| Wire protocol and packet framing | ChaCha20-Poly1305, X25519, BLAKE2/SHA-256, HKDF |
| Session management, keepalive, rekey, replay window | Noise Protocol Framework implementation (handshake pattern) |
| Client app (UI, connect/disconnect, status) | TUN device driver layer (Linux `/dev/net/tun`, Windows Wintun, macOS utun) |
| Server (peer registry, IP allocation, NAT setup) | Standard library networking |
| Routing/DNS setup on each OS | |
| Config, key tooling, tests, docs | |

Be upfront in the README: *"Educational reimplementation of VPN concepts, inspired by WireGuard; cryptography uses vetted libraries; not security-audited."* WireGuard already exists and is excellent, and saying you know that makes you look more credible, not less.

---

## 3. Target Platforms (Decision Needed From Owner)

| Component | Platform |
|-----------|----------|
| **Server** | Linux (Ubuntu) on a free-tier VM, or a local Linux VM for early testing |
| **Client v1** | **Choose one primary:** Windows *or* Linux *or* macOS (the owner's laptop OS) |
| Client v1.1 | A second OS |

> **Owner:** replace this line with your laptop OS before starting: `PRIMARY CLIENT OS = ______`. The agent should build and test on that OS first.

All client OSes need **administrator/root rights** to create a virtual network adapter and change routes. The app must request elevation clearly.

---

## 4. Tech Stack (Recommended)

**Language: Go**, not Python.

Reasons: single static binary per OS, easy cross-compilation, first-class concurrency for packet loops, mature TUN libraries on all three OSes, and good performance. Python is a poor fit for per-packet processing and for Windows virtual adapters.

| Layer | Choice |
|-------|--------|
| Language | Go 1.22+ |
| TUN device | `golang.zx2c4.com/wireguard/tun` (cross-platform TUN abstraction; Windows uses Wintun, a free driver bundled as a DLL) |
| Handshake | Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s` via `github.com/flynn/noise` |
| AEAD / KDF | `golang.org/x/crypto` (chacha20poly1305, hkdf, curve25519) |
| Transport | UDP |
| Client UI | **Local web UI served by the client binary** (embedded HTML/JS, opens in a small window or browser) for v1; optional **Wails** desktop shell later |
| Config | YAML or TOML |
| Logging | Go `log/slog` |
| Tests | `go test`, plus integration tests using network namespaces on Linux |
| Server deploy | systemd unit; optional Docker (needs `--cap-add=NET_ADMIN` and `/dev/net/tun`) |

> Antigravity note: tell the agent to verify library names and versions against the actual package registry when adding dependencies, rather than guessing.

---

## 5. System Architecture

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

### 5.1 Packet Flow (the pipeline to understand)
1. App sends a packet; the OS routes it to the TUN adapter (because the default route points there).
2. Tunnel engine reads the raw IP packet from TUN.
3. Packet is wrapped in a data frame and encrypted with the session key (AEAD, unique counter nonce).
4. Frame goes out over UDP to the server (this destination is excluded from the tunnel route to avoid a loop).
5. Server looks up the session, authenticates and decrypts, checks the replay window, and writes the inner packet to its TUN.
6. Linux forwards it and **NAT** rewrites the source to the server's public IP; the website replies to the server.
7. Reply arrives at the server TUN, is matched to the correct client, encrypted, and sent back.
8. Client decrypts and writes the packet to its TUN; the app receives it.

---

## 6. Functional Requirements

### Must Have (MVP)
- **FR-1** Server and client binaries from one codebase (`tunnel server`, `tunnel client`) plus a key tool (`tunnel genkey`, `tunnel pubkey`).
- **FR-2** Each device has a **static X25519 keypair**. Server config lists authorized client public keys and the IP each gets (e.g. `10.7.0.2`). Client config holds the server's public key and endpoint. No passwords.
- **FR-3** Mutual-authenticated handshake via Noise IK, producing separate send/receive session keys.
- **FR-4** Encrypted data transport over UDP using ChaCha20-Poly1305 with a monotonically increasing counter nonce per direction.
- **FR-5** Replay protection (sliding window) and rejection of any frame that fails authentication, silently (don't reply to unauthenticated packets).
- **FR-6** Client creates a TUN adapter, assigns its tunnel IP, sets **default route through the tunnel**, and keeps a **host route to the server's real IP via the original gateway**.
- **FR-7** Server creates a TUN adapter, enables IP forwarding, and installs NAT (masquerade) rules; **cleans them up on exit**.
- **FR-8** DNS: client points DNS at a resolver reachable through the tunnel and restores original DNS on disconnect.
- **FR-9** **Clean disconnect and crash safety:** restore routes and DNS on exit, SIGINT/Ctrl+C, and a `tunnel client --repair` command that fixes a broken network state.
- **FR-10** Keepalive packets, dead-peer detection, and automatic reconnect after network change or timeout.
- **FR-11** Rekey automatically after a time limit (e.g. 2 minutes) or a data limit.
- **FR-12** Client UI: Connect/Disconnect button, status (connected, handshake time, latency), bytes up/down, current public IP, server name.
- **FR-13** Logs never include packet contents or destination addresses.

### Should Have
- **FR-14** MTU handling (default tunnel MTU ~1380, configurable) and MSS clamping on the server to avoid hanging pages.
- **FR-15** IPv6 leak protection: either tunnel IPv6 or block it while connected.
- **FR-16** Kill switch (block non-tunnel traffic if the tunnel drops), optional toggle.
- **FR-17** Multiple client peers on the server with per-peer stats.
- **FR-18** Config import/export and `tunnel status` CLI command.
- **FR-19** Server rate limiting of handshake attempts (cookie/DoS mitigation, kept simple).

### Could Have
- **FR-20** Second client OS; packaged installer; system-tray icon.
- **FR-21** Wails desktop shell instead of local web UI.
- **FR-22** Admin web panel on the server for adding peers and viewing stats.
- **FR-23** Multiple servers selectable in the client.

---

## 7. Protocol Specification (Draft for Agent to Refine in `docs/protocol.md`)

- **Transport:** UDP, default port 51820 (configurable; avoid using exactly WireGuard's default if both could run on one box).
- **Handshake:** `Noise_IK_25519_ChaChaPoly_BLAKE2s`. Client knows the server's static public key in advance; the client initiates; the server responds; both derive transport keys.
- **Message types** (1-byte type field):
  - `0x01` Handshake initiation
  - `0x02` Handshake response
  - `0x03` Transport data (receiver session ID + 8-byte counter + AEAD ciphertext)
  - `0x04` Keepalive (empty transport data)
- **Sessions:** random 32-bit session IDs identify the peer's session without exposing static keys on the wire.
- **Nonce:** 64-bit counter per direction; sender never reuses; receiver tracks a replay window (e.g. 2048 bits).
- **Padding:** pad plaintext to a multiple of 16 bytes (optional; weakens length leakage slightly).
- **Limits:** max UDP payload sized from MTU; drop oversized frames.
- **Roaming:** server updates a peer's endpoint only after a frame **authenticates**.
- **Rekey:** initiate a new handshake after the time or data limit; switch keys without dropping traffic.

---

## 8. Non-Functional Requirements

**Security**
- Only vetted primitives (Section 2). **No custom handshake, cipher, or nonce scheme.**
- Private keys in files with owner-only permissions; never in Git; never logged.
- Constant-time comparisons where relevant (library-provided).
- Server ignores all packets that don't authenticate (no error replies).
- Run the server as an unprivileged user with only the needed capabilities (`CAP_NET_ADMIN`) where practical.
- README states plainly: educational, not audited.

**Reliability:** survive Wi-Fi changes, sleep/resume, and server restart without manual repair; never leave the OS with broken routes after exit or crash.

**Performance (targets, not promises):** ≥ 50 Mbps on a laptop to a nearby server; added latency under 10 ms excluding network distance.

**Usability:** setup in under 15 minutes from the README; one command to generate keys; one click to connect.

**Privacy:** no traffic logs; document exactly what is and isn't logged.

**Cost:** $0.

---

## 9. Repository Structure

```
tunnel/
├── docs/ (PRD.md, architecture.md, protocol.md, threat-model.md, setup-server.md, setup-client.md, learning-notes.md)
├── cmd/
│   └── tunnel/main.go              # subcommands: server | client | genkey | pubkey | status
├── internal/
│   ├── crypto/                     # Noise wrapper, key handling
│   ├── protocol/                   # message encode/decode
│   ├── session/                    # sessions, counters, replay window, rekey
│   ├── tunnel/                     # packet loops: TUN <-> UDP
│   ├── tun/                        # TUN abstraction + per-OS setup
│   ├── netcfg/                     # routes, DNS, NAT, per-OS (linux/windows/darwin files)
│   ├── server/                     # peer registry, IP allocation
│   ├── client/                     # connect state machine, reconnect
│   ├── ui/                         # embedded web UI + local API (static/)
│   └── config/
├── test/                           # integration tests (Linux netns)
├── scripts/                        # server setup, systemd unit, firewall helper
├── configs/ (server.example.yaml, client.example.yaml)
├── Makefile                        # build for linux/windows/darwin
├── .gitignore
└── README.md
```

---

## 10. Milestones & Acceptance Criteria

| # | Milestone | Done when |
|---|-----------|-----------|
| **M0** | Setup | Go installed, repo + module created, Makefile builds a "hello" binary for the primary OS, CI runs `go test` |
| **M1** | **Concept lab (no code from the agent without explanation)** | You can explain TUN, routing table, NAT, MTU in `learning-notes.md` and demo a TUN device ping on Linux VM |
| **M2** | Plaintext UDP tunnel | Two machines (or two network namespaces) exchange raw IP packets through TUN ↔ UDP, **unencrypted**, so ping works across them |
| **M3** | Key tool + Noise handshake | `genkey/pubkey` work; handshake succeeds with right keys, fails with wrong ones (tests prove it) |
| **M4** | Encrypted transport | Data frames use AEAD with counters; replay and tamper tests pass; Wireshark capture shows only ciphertext |
| **M5** | Server NAT + internet | A Linux client gets internet **through the server**: `curl ifconfig.me` shows the server's IP |
| **M6** | Client routing + DNS on your primary OS | Default route and DNS switch on connect and **fully restore** on disconnect, crash, and `--repair` |
| **M7** | Reliability | Keepalive, dead-peer detection, auto-reconnect, rekey all tested (disconnect Wi-Fi, sleep laptop, restart server) |
| **M8** | Cloud server | Server on a free-tier VM; connect from home; browsing and video work |
| **M9** | UI | Connect button, status, handshake time, bytes, public IP, errors in plain language |
| **M10** | Hardening | MTU/MSS tuning, IPv6 handling, kill switch (optional), handshake rate limiting, secret scan, least-privilege server |
| **M11** | Security review | Threat model written; agent security-review pass; fixes applied |
| **M12** | Portfolio polish | README, diagrams, protocol spec, demo video, "Built with AI" section |
| **M13** | Stretch | Second OS, installer, admin panel, tray icon |

> **Suggested order to stay sane:** do M2 to M5 entirely on Linux (VM or the free cloud server). Only then fight the Windows/macOS routing and driver details in M6.

---

## 11. Testing Plan

| Type | What |
|------|------|
| Unit | Replay window, counter/nonce handling, message parse/serialize (including malformed input), IP allocation, config validation |
| Fuzz | Go's built-in fuzzing on the protocol parser (agent should add it) |
| Integration | Linux network namespaces: client ns ↔ server ns ↔ fake "internet" ns, automated |
| Security | Wireshark shows no plaintext; wrong key rejected; replayed packet dropped; tampered packet dropped; unauthenticated packets get **no response** |
| Leak | Public IP check, DNS leak test, IPv6 leak test, test after sudden disconnect |
| Recovery | Kill client process mid-session; routes and DNS must be recoverable with `--repair` |
| Real-world | Home Wi-Fi, mobile hotspot, campus Wi-Fi (some block UDP), sleep/resume |

---

## 12. Risks

| Risk | Mitigation |
|------|-----------|
| **Locking yourself out of your own network** (bad routes/DNS) | Build `--repair` first (FR-9); test in a VM before the host; keep a way to reboot to clear routes |
| Routing loop (tunnel packets routed into the tunnel) | Host route to the server via original gateway (FR-6); test explicitly |
| Windows/macOS driver and privilege complexity | Do Linux first; use the maintained TUN library; bundle Wintun DLL; keep OS code isolated in `netcfg/` |
| AI agent writes subtly unsafe crypto or nonce logic | Only vetted libs; protocol section is the contract; mandatory tests; run the security-review prompt |
| "Pages hang" from MTU | Configurable MTU, MSS clamping, test with large downloads |
| Free server unavailable | Oracle Always Free (verify current terms; needs card verification), student credits, or a home Linux box if your ISP allows port forwarding |
| Campus/ISP blocks UDP | Test early; stretch goal: TCP/443 fallback transport |
| Project too big | Milestones are shippable stages; M5 alone (Linux full-tunnel VPN) is already a strong project |
| Over-claiming security | Honest README and threat model |
| Terms of service / law | Use on your own devices and server, check hosting provider's terms, follow local law |

---

## 13. Antigravity Workflow Guide

**Rules to paste at the start of every new agent session:**
> You are helping a beginner build the project in docs/PRD.md. Rules: (1) One milestone at a time. (2) Before writing code or running commands that change my network or system, show a short plan and wait for my approval. (3) Explain what each file and command does in plain language. (4) Use only vetted crypto libraries as listed in the PRD; never design your own handshake, cipher or nonce scheme. (5) Verify dependency names and versions from the real registry. (6) Never commit secrets or private keys. (7) Anything that changes routes, DNS or firewall must be reversible and tested in a VM or network namespace first. (8) After each milestone run tests and show me the results. (9) Tell me exactly what I must do manually.

**M0 prompt:**
> Read docs/PRD.md. Do M0 only. Ask me which OS my laptop uses if PRIMARY CLIENT OS is blank. Set up the Go project structure from Section 9, a Makefile, a .gitignore, a stub README and a CI workflow. Explain each piece and wait.

**Milestone template:**
> Do Milestone [N] from docs/PRD.md. First give me a plan: files, tests, what could go wrong, and what I need to do manually. After I approve, implement, test, and summarize what I should understand.

**Viva prompt (after each milestone):**
> Explain what we just built as if I must defend it in a viva. Ask me 3 questions, correct my answers, and add the corrected notes to docs/learning-notes.md.

**Security review prompt (M11):**
> Act as an adversarial security reviewer. Using docs/protocol.md and Section 8 of docs/PRD.md, review the code for nonce reuse, replay, key handling, parser bugs, DoS, privilege issues, and route/DNS leaks. List real risks by severity with file references.

---

## 14. Definition of Done
- [ ] On the primary OS, pressing Connect makes `ifconfig.me` show the server's IP with no proxy settings
- [ ] Disconnect, crash, and `--repair` all restore normal networking
- [ ] Wireshark shows only ciphertext; replay and tamper tests pass
- [ ] Survives Wi-Fi switch, sleep/resume, and server restart
- [ ] Server runs on a free cloud VM for at least a week of testing
- [ ] No secrets in Git history; keys stored with safe permissions
- [ ] `docs/protocol.md` and `docs/threat-model.md` are written
- [ ] README: honest scope, "inspired by WireGuard", "Built with AI" section, setup in under 15 minutes
- [ ] Demo video recorded
- [ ] You can explain the full packet flow and the handshake without notes

---

## 15. Open Decisions (Owner to Fill In)
1. `PRIMARY CLIENT OS = ______`
2. Server location: Oracle free VM / other / local VM first
3. App name (working title "Tunnel")
4. UI: local web UI (default) or Wails desktop shell

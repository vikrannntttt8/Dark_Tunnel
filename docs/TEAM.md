# Team Work Split — Two-Person VPN Project

> Companion to `docs/PRD.md` (v3). Save as `docs/TEAM.md`. Milestone numbers (M0–M13) refer to the PRD.
> Names are placeholders: **Person A = "Network & Systems"**, **Person B = "Protocol & App"**. Decide who is who in Section 6.

---

## 1. The Idea Behind the Split

The project has two halves that only meet at a clean boundary:

- **The pipe:** getting raw packets in and out of the OS (virtual adapter, routes, DNS, NAT, server, cloud). This is OS-level and hands-on.
- **The secret sauce:** deciding what goes on the wire and keeping it secure (handshake, encryption, sessions, rekeying), plus the app people actually see.

Each half can be built and tested **without waiting for the other**, then joined at agreed interfaces. That avoids two people editing the same files.

| | **Person A: Network & Systems** | **Person B: Protocol & App** |
|---|---|---|
| Theme | "Packets move through the OS and the internet" | "Packets are secure, sessions are reliable, users can operate it" |
| Folders owned | `internal/tun/`, `internal/netcfg/`, `internal/server/`, `scripts/`, `test/` (netns integration) | `internal/crypto/`, `internal/protocol/`, `internal/session/`, `internal/client/`, `internal/ui/`, `configs/` |
| Shared (both edit carefully) | `internal/tunnel/`, `cmd/tunnel/`, `docs/`, `README.md` | same |

---

## 2. Who Does What (by PRD Milestone)

| Milestone | Together | Person A | Person B |
|-----------|:-------:|----------|----------|
| **M0** Setup | ✅ | Go install, Makefile, CI | Repo, `.gitignore`, folder structure, **write the interface contracts (Section 3)** |
| **M1** Concept lab | ✅ | TUN, routing table, NAT, MTU notes + Linux VM TUN ping demo | Noise handshake, AEAD, nonces, replay notes |
| **M2** Plaintext UDP tunnel | | **Owner:** TUN ↔ UDP packet loops | Reviews; builds test packet generator |
| **M3** Keys + Noise handshake | | Reviews | **Owner:** `genkey/pubkey`, Noise IK handshake, tests |
| **M4** Encrypted transport | ✅ | Plug session into the tunnel loops | **Owner:** AEAD frames, counters, replay window, tamper tests; Wireshark check done together |
| **M5** Server NAT + internet | | **Owner:** IP forwarding, NAT rules + cleanup, peer IP allocation, `curl ifconfig.me` test | Server-side peer registry/config loading |
| **M6** Client routing + DNS | | **Owner:** routes, DNS, host-route to server, restore on exit, `--repair` | Client connect state machine hooks that call these |
| **M7** Reliability | | Network-change handling, sleep/resume testing | **Owner:** keepalive, dead-peer detection, reconnect, rekey |
| **M8** Cloud server | | **Owner:** free VM, firewall rules, systemd, deployment guide | Config for remote endpoint, key distribution steps |
| **M9** UI | | Local API endpoints for status/stats data | **Owner:** web UI, Connect button, stats, error messages |
| **M10** Hardening | | **Owner:** MTU/MSS, IPv6 handling, kill switch, least-privilege server | **Owner:** handshake rate limiting, fuzz tests, secret scan |
| **M11** Security review | ✅ | Reviews network/privilege/leak findings | Writes threat model; runs reviewer prompt on protocol code |
| **M12** Polish | ✅ | Server/setup docs, architecture diagram | README, protocol spec, demo video |
| **M13** Stretch | | Second OS support, installer | Tray icon / Wails shell, admin panel |

**Rough effort balance:** about 50/50. A's work is more OS-debugging heavy; B's is more design/test heavy. If one side feels lighter, B can also take the Linux server-side work in M5, or A can own the admin panel.

---

## 3. Interface Contracts (Agree on These in M0, Then Don't Change Silently)

Write these as Go interfaces in one file (`internal/contracts/contracts.go`) so both agents code against the same shapes. Example shapes (agent will refine):

```go
// Owned by A, used by B and shared code
type TunDevice interface {
    ReadPacket() ([]byte, error)     // one raw IP packet from the OS
    WritePacket(p []byte) error      // inject one raw IP packet into the OS
    Close() error
}

type NetConfigurator interface {
    Apply() error     // set tunnel IP, routes, DNS (or NAT on server)
    Revert() error    // restore everything; safe to call twice
}

// Owned by B, used by A and shared code
type Session interface {
    Encrypt(plaintext []byte) (frame []byte, err error)
    Decrypt(frame []byte) (plaintext []byte, err error)
}

type Handshaker interface {
    // Client: start handshake with server's static public key
    // Server: accept initiation from any authorized client key
    // Returns an established Session
}
```

**Rule:** if you need to change an interface, tell your partner first, update the file in a small PR, and merge it before building on it.

**How you stay unblocked:**
- A tests the tunnel with a **fake `Session`** that just copies bytes (plaintext, which is exactly M2).
- B tests crypto with a **fake `TunDevice`** (an in-memory channel), so no root access or VM is needed.

---

## 4. Working Together With Antigravity

1. **One shared GitHub repo.** Branch per milestone: `a/m5-server-nat`, `b/m4-encrypted-transport`. Never commit straight to `main`.
2. **Pull Requests:** small PRs, and the *other person* reviews. Reviewing is how you both learn the half you didn't write.
3. **Each person runs their own Antigravity agent** in their own checkout/branch. Paste the "Rules" block from PRD Section 13 at the start of each session.
4. **Shared source of truth:** `docs/PRD.md`, `docs/protocol.md`, and `contracts.go`. If an agent wants to deviate, it must update the doc and tell both of you.
5. **Tell your agent which folders are yours:** *"I own internal/tun, internal/netcfg, internal/server. Do not modify other folders without asking me."* This prevents merge conflicts from an enthusiastic agent.
6. **Sync points** (stop, merge, test together): after M0, after M4, after M6, after M8, after M10, before the demo.
7. **Weekly 30-minute handoff:** each person explains what they built to the other (use the viva prompt below). Update `docs/learning-notes.md` together.

**Cross-teach prompt (use after finishing each milestone):**
> Explain what I just built to my teammate, who owns the other half of the project. Cover what it does, the interface it exposes, how to test it, and the three most likely ways it breaks. Add the summary to docs/learning-notes.md.

---

## 5. Hardware & Environment Needs

| Need | Who | Notes |
|------|-----|-------|
| Linux environment (VM or the free cloud server) for M2–M5 | **A** (primary), B can test via fake TUN | VMs: VirtualBox/VMware/WSL2 (WSL2 TUN support varies; a real Linux VM is more reliable) |
| Client OS for M6 | Whoever's laptop OS is the primary client | The person whose laptop it is owns M6 on that OS; the other tests by running the client too |
| Oracle/free VM account | **A**, with B as backup admin | Card verification may be needed. Only one account is required |
| Domain/IP, secrets | Shared via a password manager | Never share private keys in chat or Git |

**If you run different operating systems**, that's a feature: one primary client OS each means M6 and the second-OS stretch get done in parallel.

---

## 6. Fill This In Together

| Item | Decision |
|------|----------|
| Person A (Network & Systems) | ______ |
| Person B (Protocol & App) | ______ |
| Laptop OS, Person A | ______ |
| Laptop OS, Person B | ______ |
| Primary client OS for v1 | ______ |
| Who owns the free-VM account | ______ |
| Meeting cadence | ______ |
| Who presents which part | A: ______ B: ______ |

---

## 7. Presenting & Grading Fairness (Important If This Is Coursework)

- **Both of you must be able to explain the whole system**, not just your half. Examiners often ask the "other" person about the part they didn't write.
- Keep contribution evidence: Git commit history, PR reviews, and `learning-notes.md` entries by each person.
- Be transparent in the README: *"A: network/systems; B: protocol/app; built with Antigravity; reviewed by both."*
- Check your course's rules on AI-assisted work and team projects, and follow them.

---

## 8. Risks Specific To A Team

| Risk | Fix |
|------|-----|
| Merge conflicts from both agents editing the same files | Folder ownership (Section 1), small PRs, contracts file |
| One person blocked waiting on the other | Fake `Session` / fake `TunDevice` (Section 3) |
| Interfaces drift apart | Change contracts only via PR, with both approving |
| Uneven workload | Review balance at each sync point; swap tasks from the "Could Have" list |
| One person understands only their half | Cross-teach prompt and weekly handoff |
| Friend loses interest / unavailable | Everything lives in the shared repo + docs; each half is independently demo-able (A: plaintext tunnel + NAT; B: encrypted protocol tests + UI) |

# AGENTS.md

Guidance for AI agents working in this repository. Read this before making any changes.

## Priorities (in order of importance)

This project is a userspace WireGuard implementation. Everything else is secondary to these three priorities:

1. **Technical correctness above all else.** The WireGuard protocol must be implemented exactly per the [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf) and the reference implementations. Any deviation is a potential security vulnerability — the code is a security boundary and must be treated as one. When in doubt, follow the protocol, not convenience.
2. **No unexpected runtime errors.** A userspace networking stack must never crash from malformed input, race conditions, integer issues, or force-unwraps. Where correctness can't be guaranteed statically, fail a specific operation — never the process.
3. **The interface is a service that must sustain and last.** `WGInterface` is built to keep running: it must handle errors gracefully and recover where possible (e.g. channel disconnect → reconnect) instead of shutting down completely. Error handling must never take the whole service down for a per-peer or per-packet problem.

Follow these priorities when choosing between competing approaches. When a fix is ambiguous, ask the user which priority it serves rather than guessing.

## Project overview

A Swift WireGuard recreation built on SwiftNIO. It is a **userspace** implementation: the WireGuard handshake and crypto/transport logic runs as a NIO `ChannelPipeline` over a bound UDP `DatagramChannel`.

### Package layout

- **`wireguard-crypto-core`** — protocol primitives: key exchange (`dhGenerate()`), KDF/AEAD helpers, the WireGuard message types (handshake initiation/response, cookie, data), packet structures, endpoints, and TAI time support.
- **`wireguard-userspace-nio`** — the primary product: `WGInterface<C>`, a Swift `actor` conforming to `ServiceLifecycle.Service` that runs the full pipeline, plus pluggable *custom channels*.
- **`wg-test-tool`** — a CLI (`swift run wg-test-tool`) for generating keys and exercising interfaces.
- **`Tests/wireguard-swiftTests`** — Swift Testing suites: `CryptoCoreTests`, `PeerTests`, `KCPPrimitivesTests`, `WGSwiftTests`, and `LiveSocketTests` (real loopback interfaces).

### The NIO pipeline

```
 inbound → [PacketHandler] → [EncryptedPacketHandler] → [WireguardHandler] → head → body → … → tail → [DataHandoffHandler] → FIFO
 outbound ← [PacketHandler] ← [EncryptedPacketHandler] ← [WireguardHandler] ← tail ← body ← … ← head ← write
```

The WireGuard core handlers are **fixed and must not change**:

- **`PacketHandler`** — parses raw UDP datagrams into `(Endpoint, Message.NIO)`; enforces MTU limits.
- **`EncryptedPacketHandler`** — applies the `EncryptedPacketProcessor` hook (observe/mutate encrypted packets; this is the primary test injection point).
- **`WireguardHandler`** — the crypto core: handshake validation/forging, cookie logic, per-peer sessions, transport data encrypt/decrypt, sliding-window replay protection. Emits/consumes `PeerAssociated<ByteBuffer>`.
- **`DataHandoffHandler`** — yields inbound plaintext `ByteBuffer`s into each peer's `FIFO<ByteBuffer, Swift.Error>`.

The pluggable middle — **custom channels** — conforms to `CustomChannels` and is composed of a head, body channels, and a tail:
- `PeerAssociatedHeadHandler` pins the head boundary: `InboundIn`/`OutboundOut` == `PeerAssociated<ByteBuffer>`.
- `PeerAssociatedTailHandler` pins the tail boundary: `OutboundIn`/`InboundOut` == `PeerAssociated<ByteBuffer>`.
- See `ChannelHandlers/CustomChannels/Protocol.swift`. Prebuilt sets: `DefaultChannels`, `KCPChannels`, `KeepAlive`.

## Workflow requirements

- **Verify every change.** Build (`swift build`) and test (`swift test`) before declaring done.
  - The full test suite includes `LiveSocketTests` (real sockets, several minutes). Run long suites with the terminal background + notify pattern and keep working; never block a full verification on them unnecessarily.
- **Scope fixes to exactly what was asked.** If the user says "fix ONLY X", touch ONLY X. Do not bundle related changes, even ones that seem obviously correct — mention them and let the user decide.
- **Never commit** unless explicitly told to.
- **Ask before destructive commands** and before modifying files outside the requested scope. This user prefers to approve commands and file changes.
- **Do not invent or propose "standard" behavior that diverges from the protocol.** Repeatedly re-derive from the whitepaper and reference implementations.

## Protocol correctness rules (priority 1)

- The crypto/message code must match the WireGuard whitepaper: handshake cookie mechanism (M1/M2/MAC1/MAC2), `HASH/LABEL-*` domain separation, key derivation, nonce counters, padding, and the Reject-After-* constraints (messages `2⁶⁴−2¹³−1`, timeouts `keepalive 10s / rekey 120s / reject 300s`).
- **Untrusted input is hostile.** Every byte from the wire is attacker-controlled until authenticated: validate lengths, indexes, and counters before use; keep pre-curve25519 MAC1 rejection on the responder path (DoS hardening); enforce MAC2; rotate the cookie secret every two minutes with an old-secret grace period.
- Do not trust wire values as bounds (e.g. `una`, splice counts, fragment counts) without clamping. See `references/wireguard-swift-kcp.md` in the security-audit skill for the catalog of prior findings and fixes (H1–H5, M1–M6, L1–L5).
- Reject inbound messages that exceed the configured MTU **unconditionally**, and never let an over-MTU write reach the socket.
- Clean up key material: session transit keys must be zeroed on rotation/discard (`RAW.secureZeroBytes`); don't log private keys or secrets (private-key `debugDescription` must stay redacted).
- Respond under load with cookie replies rather than work; never perform DH on unauthenticated handshakes.

## Runtime-error rules (priority 2)

- **No force-unwraps or IUOs on values you can't prove safe** — especially anything derived from the wire, from NIO futures, or populated asynchronously (e.g. window IUOs set in `handlerAdded`, promises referenced after completion).
- `fatalError`/traps are only acceptable in DEBUG-gated paths or genuinely impossible internal invariants. Invalid user input, malformed packets, or degraded runtime conditions must **fail the operation, not the process** (fail the promise, drop the packet, log — never crash).
- Guard integer arithmetic that can trap: fragment IDs cast to `UInt8` (>256 segments), division by MTU/MSS (0), negative `advanced(by:)`, `UInt32(negative)`.
- NIO promises must complete exactly once; never reuse a completed `EventLoopPromise` across retransmissions.
- Prefer returning/`throwing` over traps in public API. E.g. `PeerInfo` decoding must throw on malformed input, not crash.
- Promise failures must always be propagated to whoever holds the promise (writes, config updates, channel init), so callers never hang.

## Service-resilience rules (priority 3)

- `WGInterface` is a `Service` designed to last. It must **recover**: on unexpected channel death it transitions to `.disconnected`, finishes FIFOs with the error, and attempts reconnection (currently a 5-second wait) rather than terminating.
- Per-peer or per-packet failures must be isolated: a bad packet, a failing peer, or a dropped write must not take down the whole interface or the whole `EventLoopGroup`.
- Keep-alive/rekey machinery must run per-peer and survive peer configuration updates (see `KeepAliveHandler`'s re-scheduling on `peerConfigUpdate`).
- On clean shutdown (`.terminated`), finish all FIFOs (inbound, handoff, handshake) so consumers unblock; on error, finish them **with the error**.
- Guarded access to `ChannelHandlerContext` across asynchronous tasks (see `ContextContainer`) — contexts can go stale after the channel closes.
- A peer's FIFO may be finished and replaced on configuration updates; don't retain finished FIFOs.

## Conventions

- **Swift Testing only — never XCTest.** The user rejects XCTest entirely. Use `@Suite`, `@Test`, `#expect`.
- Public API carries concise DocC `///` comments (correct spelling and grammar); comments belong *above* attributes. A DocC catalog exists at `Sources/wireguard-userspace-nio/wireguard_userspace_nio.docc/`.
- Pipeline handlers implement `channelRead`/`write`/`flush`/`channelReadComplete` with `context.eventLoop.assertInEventLoop()` in DEBUG builds and use `ContextContainer` when a task outlives the context.
- This project's **KCP channel deliberately diverges from the C KCP reference** (skywind3000/kcp). Cite the real KCP only as a guide; never propose replacing the custom implementation with a copy of the reference.
- Keep comments describing protocol behavior accurate to the code; internal invariants worth documenting (cookie rotation, precomputed MAC1 keys, Reject-After counters) are already annotated in-source.

## Useful commands

```bash
swift build                          # compile both libraries + tool
swift test                           # full suite (Live Socket Tests take minutes)
swift test --skip "Live Socket Tests"# fast feedback on unit suites
swift run wg-test-tool --help        # CLI subcommands
```

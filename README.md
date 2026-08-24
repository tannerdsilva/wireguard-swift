# wireguard-swift

A userspace WireGuard implementation for Swift, built on **SwiftNIO**. For more information on WireGuard, see https://www.wireguard.com.

This package provides two libraries:

- **`wireguard-crypto-core`** — the WireGuard protocol primitives: key exchange, handshake and data messages, packet structures, and KDF/cipher helpers.
- **`wireguard-userspace-nio`** — `WGInterface`, the primary product: a full WireGuard interface that runs as a NIO pipeline over UDP, plus pluggable *custom channels* for transport behavior.

## Installation

Add the package to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/tannerdsilva/wireguard-swift.git", from: "0.1.0")
]
```

```swift
dependencies: [
    .product(name:"wireguard-userspace-nio", package:"wireguard-swift"),
]
```

## Using WGInterface

`WGInterface<C>` is the primary product of this library. It is a Swift **actor** conforming to `ServiceLifecycle.Service`, and it is generic over `CustomChannels` (`C`).

### Dependencies

```swift
import NIO                       // ByteBuffer, Channel
import Logging                   // Logger
import RAW_dh25519               // PublicKey, MemoryGuarded<PrivateKey>
import bedrock_fifo              // FIFO
import wireguard_crypto_core     // dhGenerate()
import wireguard_userspace_nio   // WGInterface, PeerInfo, KCPChannels
```

### Creating Keys

The interface needs a static private key. Generate one with `dhGenerate()` from `wireguard-crypto-core`:

```swift
let (publicKey, privateKey) = try dhGenerate()   // (PublicKey, MemoryGuarded<PrivateKey>)
```

### Creating peer configurations

For each remote peer, create a `PeerInfo` (or `any PeerInformation`). Add the peer's endpoint and the FIFO that will receive its inbound data here:

```swift
let peerFifo = FIFO<ByteBuffer, Swift.Error>()          // where inbound plaintext lands

let peer = PeerInfo(
    publicKey: peerPublicKey,                          // the remote's public key
    ipAddress: "127.0.0.1",                            // remote endpoint host
    port: 36001,                                       // remote endpoint port
    internalKeepAlive: .seconds(20),                   // keep-alive interval
    inboundData: peerFifo                              // FIFO for data from this peer
)
```

> Note: when an interface is the *initiator* that will send the first bytes, a peer endpoint is required so the interface knows where to send the handshake. When an interface only answers inbound connections, `endpoint` may be `nil`.

### Creating and running the interface

```swift
let interface = try WGInterface<KCPChannels>(
    staticPrivateKey: privateKey,
    mtu: 1400,                                        // interface MTU in bytes
    initialConfiguration: [peer],                     // the peers from step 3
    logLevel: .debug,                                 // use .info/.critical for production
    listeningPort: 36002                              // local UDP port (default 36361)
)
```

`WGInterface` is a `Service`, so run it as a task.

```swift
try await withThrowingTaskGroup(of: Void.self) { group in
    group.addTask { try await interface.run() }

    // Wait until the underlying channel is bound and the pipeline is ready:
    try await interface.waitForChannelInit()
    ...
}
```

### Sending Data

Sending through the interface:

```swift
let payload: [UInt8] = Array("Hello, world!".utf8)
try await interface.write(publicKey: peerPublicKey, data: payload)
```

Sending through the channel:

```swift
let channel = try await interface.getChannel()       // throws if not engaged
try WGInterface<KCPChannels>.write(channel: channel, publicKey: peerPublicKey, data: ByteBuffer(bytes: payload))
```

### Receiving Data

Inbound plaintext from a peer is delivered through the FIFO attached to the peer configuration. Consume it asynchronously:

```swift
let iterator = peerFifo.makeAsyncConsumer()
if let incomingData = try await iterator.next() {
    let bytes = Array(incomingData.readableBytesView)
    // handle bytes...
}
```

### Observing handshakes

Completed handshakes are reported on a shared FIFO, one `HandshakeInfo` per handshake:

```swift
let handshakeIterator = await interface.getHandshakeFifo().makeAsyncConsumer()
if let info = try await handshakeIterator.next() {
    print("handshake with \(info.publicKey), RTT \(info.rtt.uptimeNanoseconds) ns")
}
```

### Shutting down

`WGInterface` follows the `Service` lifecycle. Cancel the running task or call `close()` for an explicit graceful shutdown:

```swift
try await interface.close()    // throws if the interface is not engaged
```

If the underlying channel dies unexpectedly (e.g. a network error), the interface records `.disconnected`, finishes its FIFOs with the error, and attempts to reconnect after 5 seconds. On a clean shutdown it finishes FIFOs gracefully and transitions to `.terminated`.

## Integrating into the NIO Pipeline

`WGInterface` owns one `DatagramBootstrap` bound to a UDP port. Every packet that crosses the interface — inbound or outbound — flows through a single NIO pipeline. That pipeline is built during channel initialization:

```
            ┌─────────────────────── custom channels ───────────────────────┐
 inbound →  [PacketHandler] → [EncryptedPacketHandler] → [WireguardHandler] → [CustomChannels] → [DataHandoffHandler] → peer FIFO
 outbound ← [PacketHandler] ← [EncryptedPacketHandler] ← [WireguardHandler] ← [CustomChannels] ← data to write
```

The WireGuard core handlers (`PacketHandler`, `EncryptedPacketHandler`, `WireguardHandler`, `DataHandoffHandler`) are fixed; the custom channels in the middle are the pluggable part.

The `EncryptedPacketHandler` can be plugged into through an `EncryptedPacketProcessor` which is primarily used for logging or testing. 

## Custom channels

Custom channels are what make `WGInterface` extensible. The pipeline has a fixed WireGuard core, but the middle — what happens to plaintext between encryption and handoff — is entirely up to the user.

### The CustomChannels protocol

Custom channel sets must conform to `CustomChannels`. The framework:

- **`CustomChannels`** — the protocol. Requires a head, a body, and a tail, plus an `init(_:mtuLimits:)` that a `WGInterface` calls to build the channels.
- **`PeerAssociatedHeadHandler`** — protocol for the head channel. Pins `InboundIn` and `OutboundOut` to `PeerAssociated<ByteBuffer>`.
- **`PeerAssociatedTailHandler`** — protocol for the tail channel. Pins `OutboundIn` and `InboundOut` to `PeerAssociated<ByteBuffer>`.
- **`PeerAssociated<T>`** — the envelope carrying a value together with the peer's public key through the channel set.

### Prebuilt channel sets

| Channel set | Head | Body | Tail | Purpose |
|---|---|---|---|---|
| **`DefaultChannels`** | `DefaultHeadChannelHandler` (pass-through) | none | `SplicerHandler` (MTU-splice) | Minimal set for plain WireGuard transport |
| **`KCPChannels`** | `KCPSegment.Handler` (segment combine/split) | `KCPControlBlock.Handler` (reliability, ordering) | `SplicerHandler` | WireGuard over a KCP-style reliable UDP wrapper |
| **`KeepAlive`** | `KeepAliveHandler` (periodic keep-alives) | none | `DropAllHandler` (drops all data) | Keeps the tunnel handshaking without carrying data |

## Requirements

- Swift 6.2+
- macOS 15+

## License

MIT — see [LICENSE](LICENSE).

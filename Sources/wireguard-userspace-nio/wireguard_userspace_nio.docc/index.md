# ``wireguard_userspace_nio``

A userspace WireGuard implementation for Swift, built on SwiftNIO.

It provides:

- `WGInterface`, the core actor that runs a WireGuard interface over a UDP NIO pipeline.
- Pluggable **Custom Channels** that sit between data encryption and data handoff, letting you choose the transport behavior of the interface.
- Supporting types for peers, handshake reporting, and encrypted-packet processing.

## Topics

### Custom Channels
- <doc:custom-channels>

### Test Handlers and Protocols
- <doc:test-handlers-and-protocols>

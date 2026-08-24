# Test Handlers and Protocols

Extension points for observing and modifying encrypted packet data as it travels between the WireGuard handler and the packet handler.

## Overview

Every `WGInterface` installs an internal `EncryptedPacketHandler` in its pipeline between the WireGuard handler and the packet handler. This handler delegates inbound and outbound processing to an `EncryptedPacketProcessor` that you provide when creating the interface:

```swift
let interface = try WGInterface<DefaultChannels>(
    staticPrivateKey: interfaceKey,
    mtu: 1420,
    logLevel: .info,
    customChannelArgs: .info,
    encryptedPacketProcessor: MyCounters()
)
```

The processor is invoked with the actual encrypted data — and, on the outbound path, the remote endpoint as well — immediately before it is written to the wire and immediately after it is received from the wire. This makes the processors suitable for testing, measuring statistics, traffic logging, or any other inspection of the encrypted traffic of an interface.

The default implementations, `DefaultEPP` and `DefaultKCPSegmentProcessor`, pass data through without modification, which is the behavior used if you omit the `encryptedPacketProcessor:` argument.

> Note: The NIO channel handlers that consume these processors — `EncryptedPacketHandler` and `KCPTestingHandler` — are internal implementation details of the package and are not part of the public API.

## Topics

### Encrypted Packet Processing

- ``EncryptedPacketProcessor``
- ``DefaultEPP``

### KCP Segment Processing

- ``KCPSegmentProcessor``
- ``DefaultKCPSegmentProcessor``

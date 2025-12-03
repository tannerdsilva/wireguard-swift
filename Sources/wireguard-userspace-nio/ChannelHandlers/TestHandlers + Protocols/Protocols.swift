import NIO
import wireguard_crypto_core

/// A protocol for adding read or write operations on data inbetween the wireguard handler and packet handler.
/// Allows modification of the content and enpoint on outbound encrypted data.
/// Allows modification of the content on inbound encrypted.
///
/// Instances of the protocol may be used for testing, measuring statistics, or any other needs.
public protocol EncryptedPacketProcessor:Sendable {
	mutating func willWriteOutbound(_ encryptedWireguardContent:inout ByteBuffer, ep:inout Endpoint)
	mutating func willReadInbound(_ encryptedWireguardContent:inout Message.NIO)
}

/// Default encrypted packet processor. Passes data through it without any modification
public struct DefaultEPP:EncryptedPacketProcessor {
	public init() {}
	mutating public func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer, ep:inout Endpoint) {}
	mutating public func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {}
}

public protocol KCPSegmentProcessor:Sendable {
	mutating func willWriteOutbound(_ encryptedWireguardContent:inout ByteBuffer)
	mutating func willReadInbound(_ encryptedWireguardContent:inout Message.NIO)
}

public struct DefaultKCPSegmentProcessor:KCPSegmentProcessor {
	public init() {}
	mutating public func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer) {}
	mutating public func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {}
}

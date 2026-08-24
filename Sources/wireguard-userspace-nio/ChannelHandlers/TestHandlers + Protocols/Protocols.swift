import NIO
import wireguard_crypto_core

/// A protocol for adding read or write operations on data between the WireGuard
/// handler and the packet handler.
///
/// Allows modification of the content and endpoint on outbound encrypted data,
/// and of the content on inbound encrypted data. Instances may be used for
/// testing, measuring statistics, or any other needs.
public protocol EncryptedPacketProcessor:Sendable {
	/// Called with outbound encrypted data before it is written to the wire.
	mutating func willWriteOutbound(_ encryptedWireguardContent:inout ByteBuffer, ep:inout Endpoint)
	/// Called with inbound encrypted data after it is received from the wire.
	mutating func willReadInbound(_ encryptedWireguardContent:inout Message.NIO)
}

/// Default encrypted packet processor. Passes data through without modification.
public struct DefaultEPP:EncryptedPacketProcessor {
	/// Creates a default encrypted packet processor.
	public init() {}
	/// Passes the outbound data through unchanged.
	mutating public func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer, ep:inout Endpoint) {}
	/// Passes the inbound data through unchanged.
	mutating public func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {}
}

/// A protocol for adding read or write operations on KCP segment data between
/// the WireGuard handler and the packet handler.
public protocol KCPSegmentProcessor:Sendable {
	/// Called with outbound encrypted data before it is written to the wire.
	mutating func willWriteOutbound(_ encryptedWireguardContent:inout ByteBuffer)
	/// Called with inbound encrypted data after it is received from the wire.
	mutating func willReadInbound(_ encryptedWireguardContent:inout Message.NIO)
}

/// Default KCP segment processor. Passes data through without modification.
public struct DefaultKCPSegmentProcessor:KCPSegmentProcessor {
	/// Creates a default KCP segment processor.
	public init() {}
	/// Passes the outbound data through unchanged.
	mutating public func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer) {}
	/// Passes the inbound data through unchanged.
	mutating public func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {}
}

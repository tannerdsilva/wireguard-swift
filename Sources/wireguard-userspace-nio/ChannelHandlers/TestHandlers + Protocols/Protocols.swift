import NIO
import wireguard_crypto_core

public protocol EncryptedPacketProcessor:Sendable {
	mutating func willWriteOutbound(_ encryptedWireguardContent:inout ByteBuffer, ep:inout Endpoint)
	mutating func willReadInbound(_ encryptedWireguardContent:inout Message.NIO)
}

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

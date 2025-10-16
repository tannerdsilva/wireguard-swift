import NIO
import Logging

/// a simple protocol that expresses that a type can provide its length when encoded to the wire.
internal protocol LenghExpressibleExchangeType:Sendable {
	/// the length of the type when encoded into a ByteBuffer
	var bytesOnWire:Int { get }
}
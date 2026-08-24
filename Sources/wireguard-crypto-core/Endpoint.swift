import RAW
import bedrock_ip

/// A network endpoint, either IPv4 or IPv6, used to reach a WireGuard peer.
public enum Endpoint:RAW_encodable, RAW_decodable, CustomDebugStringConvertible, Hashable, Equatable, Sendable {
	/// A textual representation of the endpoint.
	public var debugDescription: String {
		switch self {
			case .v4(let v4):
				return "\(v4)"
			case .v6(let v6):
				return "\(v6)"
		}
	}

	/// An IPv4 endpoint.
	@RAW_staticbuff(concat:AddressV4.self, Port.self)
	public struct V4:Sendable, Hashable, Equatable, CustomDebugStringConvertible {
		/// The IPv4 address.
		public let address:AddressV4
		/// The port.
		public let port:Port
		/// Creates an IPv4 endpoint from an address and port.
		public init(address:AddressV4, port:Port) {
			self.address = address
			self.port = port
		}
		/// A textual representation of the endpoint in `address:port` form.
		public var debugDescription: String {
			return "\(String(address)):\(port)"
		}
	}

	/// An IPv6 endpoint.
	@RAW_staticbuff(concat:AddressV6.self, Port.self)
	public struct V6:Sendable, Hashable, Equatable, CustomDebugStringConvertible {
		/// The IPv6 address.
		public let address:AddressV6
		/// The port.
		public let port:Port
		/// Creates an IPv6 endpoint from an address and port.
		public init(address:AddressV6, port:Port) {
			self.address = address
			self.port = port
		}
		/// A textual representation of the endpoint in `[address]:port` form.
		public var debugDescription: String {
			return "[\(String(address))]:\(port)"
		}
	}
	
    /// Reports the number of bytes required to encode the endpoint.
    public func RAW_encode(count: inout RAW.size_t) {
        switch self {
			case .v4(_):
				count = MemoryLayout<AddressV4>.size + MemoryLayout<Port>.size
			case .v6(_):
				count = MemoryLayout<AddressV6>.size + MemoryLayout<Port>.size
		}
	}

	/// Encodes the endpoint into `dest` and returns a pointer advanced past the written bytes.
    public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
        switch self {
			case .v4(let v4ep):
				return v4ep.RAW_encode(dest:dest)
			case .v6(let v6ep):
				return v6ep.RAW_encode(dest:dest)
		}
	}

	/// Attempts to decode an endpoint from the given raw bytes.
	/// - Returns: The decoded endpoint, or `nil` if the byte count matches neither V4 nor V6.
    public init?(RAW_decode: UnsafeRawPointer, count: RAW.size_t) {
        switch count {
			case MemoryLayout<V4>.size:
				self = .v4(Endpoint.V4(RAW_staticbuff:RAW_decode))
			case MemoryLayout<V6>.size:
				self = .v6(Endpoint.V6(RAW_staticbuff:RAW_decode))
			default:
				return nil
		}
    }
	

	/// An IPv4 endpoint.
	case v4(Endpoint.V4)
	/// An IPv6 endpoint.
	case v6(Endpoint.V6)

	/// Creates an endpoint from a generic IPC `Address` and port, choosing the
	/// concrete case based on the address family.
	public init(_ address: Address, port: Port) {
		switch address {
			case .v4(let addr):
				self = .v4(Endpoint.V4(address: addr, port: port))
			case .v6(let addr):
				self = .v6(Endpoint.V6(address: addr, port: port))
		}
	}

	/// Returns `true` if both endpoints carry the same address and port.
	public static func == (lhs: Endpoint, rhs: Endpoint) -> Bool {
		switch (lhs, rhs) {
			case (.v4(let l), .v4(let r)):
				return l.address == r.address && l.port == r.port
			case (.v6(let l), .v6(let r)):
				return l.address == r.address && l.port == r.port
			default:
				return false
		}
	}
}

extension Endpoint {
	/// A UDP port, stored as a big-endian 16-bit integer.
	@RAW_staticbuff(bytes:2)
	@RAW_staticbuff_fixedwidthinteger_type<UInt16>(bigEndian:true)
	public struct Port:Sendable, CustomDebugStringConvertible, Equatable, Hashable, Comparable, ExpressibleByIntegerLiteral {
		/// Creates a port from an integer literal, trapping if the value is out of range (debug builds only).
		public init(integerLiteral value: Int) {
			#if DEBUG
			guard value >= 0 && value <= UInt16.max else {
				fatalError("error initializing Endpoint.Port with value \(value). must be between 0 and \(UInt16.max). \(#file):\(#line)")
			}
			#endif
			self.init(RAW_native: UInt16(value))
		}
		/// A decimal representation of the port.
		public var debugDescription: String {
			return "\(RAW_native())"
		}	
	}
}

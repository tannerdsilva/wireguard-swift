import RAW
import bedrock_ip

public enum Endpoint:RAW_encodable, RAW_decodable, Hashable, Equatable, Sendable, CustomDebugStringConvertible {
	public var debugDescription: String {
		switch self {
			case .v4(let v4):
				return "\(v4)"
			case .v6(let v6):
				return "\(v6)"
		}
	}

	@RAW_staticbuff(concat:AddressV4.self, Port.self)
	public struct V4:Sendable, Hashable, Equatable, CustomDebugStringConvertible {
		public let address:AddressV4
		public let port:Port
		public init(address:AddressV4, port:Port) {
			self.address = address
			self.port = port
		}
		public var debugDescription: String {
			return "\(String(address)):\(port)"
		}
	}

	@RAW_staticbuff(concat:AddressV6.self, Port.self)
	public struct V6:Sendable, Hashable, Equatable, CustomDebugStringConvertible {
		public let address:AddressV6
		public let port:Port
		public init(address:AddressV6, port:Port) {
			self.address = address
			self.port = port
		}
		public var debugDescription: String {
			return "[\(String(address))]:\(port)"
		}
	}
	
    public func RAW_encode(count: inout RAW.size_t) {
        switch self {
			case .v4(_):
				count = MemoryLayout<AddressV4>.size + MemoryLayout<Port>.size
			case .v6(_):
				count = MemoryLayout<AddressV6>.size + MemoryLayout<Port>.size
		}
	}

    public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
        switch self {
			case .v4(let v4ep):
				return v4ep.RAW_encode(dest:dest)
			case .v6(let v6ep):
				return v6ep.RAW_encode(dest:dest)
		}
	}

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
	

	case v4(Endpoint.V4)
	case v6(Endpoint.V6)

	public init(_ address: Address, port: Port) {
		switch address {
			case .v4(let addr):
				self = .v4(Endpoint.V4(address: addr, port: port))
			case .v6(let addr):
				self = .v6(Endpoint.V6(address: addr, port: port))
		}
	}

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
	@RAW_staticbuff(bytes:2)
	@RAW_staticbuff_fixedwidthinteger_type<UInt16>(bigEndian:true)
	public struct Port:Sendable, CustomDebugStringConvertible, Equatable, Hashable, Comparable, ExpressibleByIntegerLiteral {
		public init(integerLiteral value: Int) {
			#if DEBUG
			guard value >= 0 && value <= UInt16.max else {
				fatalError("error initializing Endpoint.Port with value \(value). must be between 0 and \(UInt16.max). \(#file):\(#line)")
			}
			#endif
			self.init(RAW_native: UInt16(value))
		}
		public var debugDescription: String {
			return "\(RAW_native())"
		}	
	}
}
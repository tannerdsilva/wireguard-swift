import RAW
import RAW_base64

/// encompasses various result types from the wireguard 
public struct Result {}

extension Result {
	@RAW_staticbuff(bytes:8)
	@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
	public struct Bytes8:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		public var debugDescription:String {
			return "\(RAW_base64.encode(self))"
		}
	}

	@RAW_staticbuff(bytes:16)
	public struct Bytes16:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		public var debugDescription:String {
			return "\(RAW_base64.encode(self))"
		}
	}

	@RAW_staticbuff(bytes:24)
	public struct Bytes24:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		public var debugDescription:String {
			return "\(RAW_base64.encode(self))"
		}
	}

	@RAW_staticbuff(bytes:32)
	public struct Bytes32:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		public var debugDescription:String {
			return "\(RAW_base64.encode(self))"
		}
	}
}

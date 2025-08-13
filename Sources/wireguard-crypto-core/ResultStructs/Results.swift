import RAW
import RAW_base64

@available(*, deprecated, renamed:"Result.Bytes32")
public typealias Result32 = Result.Bytes32

@available(*, deprecated, renamed:"Result.Bytes24")
public typealias Result24 = Result.Bytes24

@available(*, deprecated, renamed:"Result.Bytes16")
public typealias Result16 = Result.Bytes16

@available(*, deprecated, renamed:"Result.Bytes8")
public typealias Result8 = Result.Bytes8

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

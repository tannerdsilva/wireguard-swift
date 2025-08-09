import RAW
import RAW_base64

@RAW_staticbuff(bytes:32)
public struct Result32:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_base64.encode(self))"
	}
}

@RAW_staticbuff(bytes:24)
public struct Result24:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_base64.encode(self))"
	}
}

@RAW_staticbuff(bytes:16)
public struct Result16:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_base64.encode(self))"
	}
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
public struct Result8:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_base64.encode(self))"
	}
}
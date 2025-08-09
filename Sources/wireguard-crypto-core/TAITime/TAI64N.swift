import RAW

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
/// represents a 64-bit unsigned integer in big-endian format
public struct _uint64_be:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
/// represents a 32-bit unsigned integer in big-endian format
public struct _uint32_be:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

@RAW_staticbuff(concat:_uint64_be.self, _uint32_be.self)
/// represents a TAI64N timestamp, which includes seconds and nanoseconds
public struct TAI64N:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	public let seconds:_uint64_be
	public let nano:_uint32_be

	public var debugDescription:String {
		return "\(seconds.RAW_native()) / \(nano.RAW_native())"
	}
}

import RAW

/// A 64-bit unsigned integer in big-endian format.
@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
public struct _uint64_be:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	/// A decimal representation of the value.
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

/// A 32-bit unsigned integer in big-endian format.
@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
public struct _uint32_be:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	/// A decimal representation of the value.
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

/// A TAI64N timestamp, consisting of seconds and nanoseconds.
@RAW_staticbuff(concat:_uint64_be.self, _uint32_be.self)
public struct TAI64N:Sendable, CustomDebugStringConvertible, Comparable, Equatable {
	/// The seconds component of the timestamp.
	public let seconds:_uint64_be
	/// The nanoseconds component of the timestamp.
	public let nano:_uint32_be

	/// A `seconds / nanoseconds` representation of the timestamp.
	public var debugDescription:String {
		return "\(seconds.RAW_native()) / \(nano.RAW_native())"
	}
}

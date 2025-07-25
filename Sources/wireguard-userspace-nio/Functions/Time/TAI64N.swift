import RAW

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
public struct _uint64_be:Sendable {}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
public struct _uint32_be:Sendable {}

@RAW_staticbuff(concat:_uint64_be.self, _uint32_be.self)
public struct TAI64N:Sendable, CustomDebugStringConvertible {
	public let seconds:_uint64_be
	public let nano:_uint32_be

	public var debugDescription: String {
		return "\(seconds.RAW_native()) / \(nano.RAW_native())"
	}
}

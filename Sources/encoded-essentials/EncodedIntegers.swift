import RAW

@RAW_staticbuff(bytes:2)
@RAW_staticbuff_fixedwidthinteger_type<UInt16>(bigEndian:true)
/// a big endian unsigned integer, 16 bits in size
public struct BEUInt16:Sendable, Hashable, Equatable {}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
/// a big endian unsigned integer, 32 bits in size
public struct BEUInt32:Sendable, Hashable, Equatable {}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
/// a big endian unsigned integer, 64 bits in size
public struct BEUInt64:Sendable, Hashable, Equatable {}
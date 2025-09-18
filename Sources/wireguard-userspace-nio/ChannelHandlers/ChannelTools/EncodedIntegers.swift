import RAW

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
internal struct EncodedUInt32:Sendable, ExpressibleByIntegerLiteral {}
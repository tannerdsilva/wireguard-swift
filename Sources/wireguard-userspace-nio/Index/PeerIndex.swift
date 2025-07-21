import RAW

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
internal struct PeerIndex:Sendable {
	internal static func random() throws -> Self {
		return try generateSecureRandomBytes(as:Self.self)
	}
}
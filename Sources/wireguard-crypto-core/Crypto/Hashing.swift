import RAW
import RAW_blake2
import RAW_hmac
import RAW_base64

/// Disambiguates rawdog v22's `Hasher.finish()`: the released 22.0.0 declares two
/// equally-constrained `finish() throws -> outType` overloads (one constrained to
/// `outType:RAW_decodable`, one to `outType:RAW_staticbuff`), so a bare `finish()`
/// call on any staticbuff output type is ambiguous. This helper invokes the
/// unambiguous `finish(into:)` member and returns the fixed-size output value.
public extension RAW_blake2.Hasher where outType:RAW_staticbuff & RAW_accessible_mutable, outType.RAW_fixed_type == funcType.RAW_blake2_func_impl_outtype.RAW_fixed_type {
	mutating func finishDecoded() throws -> outType {
		return try withUnsafeTemporaryAllocation(byteCount:MemoryLayout<outType.RAW_fixed_type>.size, alignment:MemoryLayout<outType>.alignment) { buffer in
			buffer.initializeMemory(as:UInt8.self, repeating:0)
			try finish(into: buffer.baseAddress!)
			return UnsafeRawPointer(buffer.baseAddress!).load(as: outType.self)
		}
	}
}

internal func wgHash<A>(_ data:borrowing A) throws -> Result.Bytes32 where A:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result.Bytes32>()
	try newHasher.update(data)
	return try newHasher.finishDecoded()
}

/// A BLAKE2s hasher producing a `K`-byte digest, as used by the WireGuard protocol.
public typealias WGHasher<K> = RAW_blake2.Hasher<S, K> where K:RAW_staticbuff

internal func wgMAC<K, A>(key:consuming K, data:consuming A) throws -> Result.Bytes16 where A:RAW_accessible, K:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, [UInt8]>(key:key, outputLength:MemoryLayout<Result.Bytes16.RAW_fixed_type>.size)
	try newHasher.update(data)
	let macBytes = try newHasher.finish()
	return macBytes.withUnsafeBytes { raw in
		return Result.Bytes16(RAW_decode:raw)!
	}
}

internal func wgHMACv2(key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> Result.Bytes32 {
	var hmac = try HMAC<RAW_blake2.Hasher<S, Result.Bytes32>>(key:key, count:keyCount)
	try hmac.update(message:data, count:dataCount)
	return try hmac.finish()
}

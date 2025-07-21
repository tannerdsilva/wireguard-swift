import RAW
import RAW_blake2
import RAW_hmac

@RAW_staticbuff(bytes:32)
internal struct Result32:Sendable, Hashable, Equatable, Comparable {}
internal func wgHash<A>(_ data:borrowing A) throws -> Result32 where A:RAW_accessible {
	let result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:32)
	defer { result.deallocate() }
	var newHasher = try RAW_blake2.Hasher<S, Result32>()
	try newHasher.update(data)
	return try newHasher.finish()
}
internal typealias WGHasher = RAW_blake2.Hasher<S, Result32>

@RAW_staticbuff(bytes:16)
internal struct Result16:Sendable, Hashable, Equatable, Comparable {}
internal func wgMac<K, A>(key:UnsafePointer<K>, data:borrowing A) throws -> Result16 where A:RAW_accessible, K:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result16>(key:key)
	try newHasher.update(data)
	return try newHasher.finish()
}

internal func wgHmac<K, A>(key:UnsafePointer<K>, data:borrowing A) throws -> Result32 where A:RAW_accessible, K:RAW_accessible {
	var hmac = try HMAC<RAW_blake2.Hasher<S, Result32>>(key:key)
	try hmac.update(message:data)
	return try hmac.finish()
}

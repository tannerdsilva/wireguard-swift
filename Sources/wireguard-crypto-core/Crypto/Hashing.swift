import RAW
import RAW_blake2
import RAW_hmac
import RAW_base64

internal func wgHash<A>(_ data:borrowing A) throws -> Result.Bytes32 where A:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result.Bytes32>()
	try newHasher.update(data)
	return try newHasher.finish()
}

public typealias WGHasher<K> = RAW_blake2.Hasher<S, K> where K:RAW_staticbuff

internal func wgMAC<K, A>(key:consuming K, data:consuming A) throws -> Result.Bytes16 where A:RAW_accessible, K:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result.Bytes16>(key:key)
	try newHasher.update(data)
	return try newHasher.finish()
}

internal func wgHMACv2(key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> Result.Bytes32 {
	var hmac = try HMAC<RAW_blake2.Hasher<S, Result.Bytes32>>(key:key, count:keyCount)
	try hmac.update(message:data, count:dataCount)
	return try hmac.finish()
}

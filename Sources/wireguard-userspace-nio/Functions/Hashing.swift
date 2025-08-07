import RAW
import RAW_blake2
import RAW_hmac
import RAW_base64

@RAW_staticbuff(bytes:32)
internal struct Result32:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	internal var debugDescription: String {
		return "\(RAW_base64.encode(self))"
	}
}
internal func wgHash<A>(_ data:borrowing A) throws -> Result32 where A:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result32>()
	try newHasher.update(data)
	return try newHasher.finish()
}
internal typealias WGHasherV2<K> = RAW_blake2.Hasher<S, K> where K:RAW_staticbuff

@RAW_staticbuff(bytes:16)
internal struct Result16:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
	internal var debugDescription:String {
		return "\(RAW_base64.encode(self))"
	}
}

internal func wgMac<K, A>(key:consuming K, data:consuming A) throws -> Result16 where A:RAW_accessible, K:RAW_accessible {
	var newHasher = try RAW_blake2.Hasher<S, Result16>(key:key)
	try newHasher.update(data)
	return try newHasher.finish()
}

internal func wgMACv2(key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> Result16 {
	var newHasher = try RAW_blake2.Hasher<S, Result16>(key:key, count:keyCount)
	try newHasher.update(data, count:dataCount)
	return try newHasher.finish()
}
internal func wgHmac<K, A>(key:consuming K, data:consuming A) throws -> Result32 where A:RAW_accessible, K:RAW_accessible {
	var hmac = try HMAC<RAW_blake2.Hasher<S, Result32>>(key:key)
	try hmac.update(message:data)
	return try hmac.finish()
}

internal func wgHMACv2(key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> Result32 {
	var hmac = try HMAC<RAW_blake2.Hasher<S, Result32>>(key:key, count:keyCount)
	try hmac.update(message:data, count:dataCount)
	return try hmac.finish()
}

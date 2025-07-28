import RAW
import RAW_dh25519

public typealias Key = RAW_dh25519.PublicKey

internal func wgKDF<K, A>(key:consuming K, data:consuming A, type:UInt8) throws -> [Result32] where A:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key.RAW_staticbuff_storetype {
   	let genKey = try wgHmac(key:key, data:data) /* T0 = HMAC(key,input)*/
	var previous = genKey
	return try [Result32](unsafeUninitializedCapacity:Int(type)) { resultBuffer, resultCount in
		for i in 1...type {
			if i == 1 {
				// first iteration
				// t1 = HMAC(T0, 0x1)
				let t1 = try wgHmac(key:genKey, data:[1])
				previous = t1
				resultBuffer[0] = t1
			} else {
				// nth case scenario
				// ti = HMAC(T0, ti-1 || 0xi)
				previous = try wgHmac(key:genKey, data:[UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
					previous.RAW_encode(dest:buffer.baseAddress!).pointee = i
					count = MemoryLayout<Result32>.size + 1
				})
				resultBuffer[Int(i) - 1] = previous
			}
		}
		resultCount = Int(type)
	}
}

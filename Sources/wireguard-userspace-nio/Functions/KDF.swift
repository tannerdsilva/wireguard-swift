import RAW

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

internal func wgKDFv2(key:UnsafeBufferPointer<UInt8>, data:UnsafeBufferPointer<UInt8>, type:UInt8) throws -> [Result32] {
	try wgHMACv2(key:key, data:data.baseAddress, dataCount:data.count).RAW_access { genKeyBuffer in // t0 = HMAC(key, input)
		var previous = Result16(RAW_decode:genKeyBuffer.baseAddress!, count:genKeyBuffer.count)
		return try [Result32](unsafeUnitializedCapacity:Int(type)) { resultBuffer, resultCount in
			for i in 1...type {
				if i == 1 {
					// t1 = HMAC(t0, 0x1)
					previous = try wgHMAC(key:genKeyBuffer, data:[1])
				} else {
				
				}
			}
		}
}
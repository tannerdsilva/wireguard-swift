import RAW

// internal func kdf(n:size_t, key:Key, data:borrowing [UInt8]) throws -> [Result32] {
// 	let workBuffer = UnsafeMutableBufferPointer<Result32>.allocate(capacity:n)
// 	defer { workBuffer.deallocate() }
// 	// find the entropy from the data
// 	let genKey:Result32 = try wgHmac(key:key, data:data)
// 	var previous:Result32 = genKey
// 	for i in 1...n {
// 		let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
// 			previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(i)
// 			count = MemoryLayout<Result32>.size + 1
// 		}
// 		let output: Result32 = try wgHmac(key:key, data:input)
// 		workBuffer[i-1] = output
// 		previous = output
// 	}
// 	return Array(workBuffer)
// }

internal func wgKDF<K, A>(key:UnsafePointer<K>, data:borrowing A, returning:(Result32).Type) throws -> Result32 where A:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key.RAW_staticbuff_storetype {
	// find the entropy from the data
	let byteBuffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:MemoryLayout<Result32>.size + 1)
	defer {
//		secureZeroBytes(byteBuffer)
		byteBuffer.deallocate()
	}
	// find the entropy from the data
	let genKey:Result32 = try wgHmac(key:key, data:data)
	var previous:Result32 = genKey
	return try wgHmac(key:key, data:[UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
		previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(1)
		count = MemoryLayout<Result32>.size + 1
	})
}

internal func wgKDF<K, A>(key:UnsafePointer<K>, data:borrowing A, returning:(Result32, Result32).Type) throws -> (Result32, Result32) where A:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key.RAW_staticbuff_storetype {
	let workBuffer = UnsafeMutableBufferPointer<Result32>.allocate(capacity:2)
	defer { workBuffer.deallocate() }
	// find the entropy from the data
	let genKey:Result32 = try wgHmac(key:key, data:data)
	var previous:Result32 = genKey
	for i in 1...2 {
		let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
			previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(i)
			count = MemoryLayout<Result32>.size + 1
		}
		let output:Result32 = try wgHmac(key:key, data:input)
		workBuffer[i-1] = output
		previous = output
	}
	return (workBuffer[0], workBuffer[1])
}

import RAW
import RAW_dh25519

public typealias Key = RAW_dh25519.PublicKey

public func wgKDFv2<T>(_ outputType:(Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:consuming T) throws -> Result32 where T:RAW_staticbuff {
	return try data.RAW_access_staticbuff { dataBuff in
		return try wgKDFv2(outputType, key:key, count:keyCount, data:dataBuff, count:MemoryLayout<T>.size)
	}
}

public func wgKDFv2(_ outputType:(Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> Result32 {
	try wgHMACv2(key:key, count:keyCount, data:data, count:dataCount).RAW_access_staticbuff { genKeyPtr in
		return try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[1], count:1)
	}
}

public func wgKDFv2<T>(_ outputType:(Result32, Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:consuming T) throws -> (Result32, Result32) where T:RAW_staticbuff {
	return try data.RAW_access_staticbuff { dataBuff in
		return try wgKDFv2(outputType, key:key, count:keyCount, data:dataBuff, count:MemoryLayout<T>.size)
	}
}

public func wgKDFv2(_ outputType:(Result32, Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> (Result32, Result32) {
	try wgHMACv2(key:key, count:keyCount, data:data, count:dataCount).RAW_access_staticbuff { genKeyPtr in
		let t1 = try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[1], count:1)
		let length = MemoryLayout<Result32>.size + 1
		let t2 = try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[UInt8](unsafeUninitializedCapacity: length, initializingWith: { buffer, count in
			t1.RAW_encode(dest:buffer.baseAddress!).pointee = 2
			count = length
		}), count: length)
		return (t1, t2)
	}
}

public func wgKDFv2<T>(_ outputType:(Result32, Result32, Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:consuming T) throws -> (Result32, Result32, Result32) where T:RAW_staticbuff {
	return try data.RAW_access_staticbuff { dataBuff in
		return try wgKDFv2(outputType, key:key, count:keyCount, data:dataBuff, count:MemoryLayout<T>.size)
	}
}

public func wgKDFv2(_ outputType:(Result32, Result32, Result32).Type, key:UnsafeRawPointer, count keyCount:size_t, data:UnsafeRawPointer, count dataCount:size_t) throws -> (Result32, Result32, Result32) {
	try wgHMACv2(key:key, count:keyCount, data:data, count:dataCount).RAW_access_staticbuff { genKeyPtr in
		let t1 = try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[1], count:1)
		let length = MemoryLayout<Result32>.size + 1
		let t2 = try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[UInt8](unsafeUninitializedCapacity: length, initializingWith: { buffer, count in
			t1.RAW_encode(dest:buffer.baseAddress!).pointee = 2
			count = length
		}), count: length)
		let t3 = try wgHMACv2(key:genKeyPtr, count:MemoryLayout<Result32>.size, data:[UInt8](unsafeUninitializedCapacity: length, initializingWith: { buffer, count in
			t2.RAW_encode(dest:buffer.baseAddress!).pointee = 3
			count = length
		}), count: length)
		return (t1, t2, t3)
	}
}

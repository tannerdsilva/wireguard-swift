import RAW
import RAW_dh25519
import RAW_chachapoly

internal func aeadEncrypt<A, D, K>(key:UnsafePointer<K>, counter:UInt64, text:UnsafePointer<A>, aad:UnsafePointer<D>) throws -> (A, Tag) where A:RAW_accessible, A:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_fixed_type == Key32.RAW_fixed_type {
	var context = RAW_chachapoly.Context(key:UnsafeRawBufferPointer(start:UnsafeRawPointer(key), count:MemoryLayout<K.RAW_fixed_type>.size))!
	return try text.pointee.RAW_access_immutable { textBuff in
		let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:textBuff.count)
		defer { cipherText.deallocate() }
		let tag = try aad.pointee.RAW_access_immutable { aadBuff in
			return try CountedNonce(counter: counter).RAW_access_immutable(UnsafeRawBufferPointer.self) { 
				try context.encrypt(nonce:$0.load(fromByteOffset:0, as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
		return (A(RAW_decode:UnsafeRawBufferPointer(start:cipherText.baseAddress!, count: textBuff.count))!, tag)
	}
}

internal func aeadEncryptV3(plaintext:UnsafeRawBufferPointer, key:UnsafeRawBufferPointer, counter:UInt64, cipherText cipherTextPtr:UnsafeMutableRawPointer, aad aadPtr:UnsafeRawBufferPointer, tag:UnsafeMutableRawPointer) throws {
	var context = RAW_chachapoly.Context(key:key)!
	return try CountedNonce(counter: counter).RAW_access_immutable(UnsafeRawBufferPointer.self) { 
		return try context.encrypt(nonce:$0.baseAddress!, associatedData:aadPtr, inputData:plaintext, output:cipherTextPtr, tag:tag)
	}
}

internal func aeadDecrypt<A, D, K>(key:UnsafePointer<K>, counter:UInt64, cipherText:UnsafePointer<A>, aad:UnsafePointer<D>, tag:Tag) throws -> A where A:RAW_accessible, A:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_fixed_type == Key32.RAW_fixed_type {
	var context = RAW_chachapoly.Context(key:UnsafeRawBufferPointer(start:UnsafeRawPointer(key), count:MemoryLayout<K.RAW_fixed_type>.size))!
	return try cipherText.pointee.RAW_access_immutable { cipherTextBuff in
		let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherTextBuff.count)
		defer { plainText.deallocate() }
		try aad.pointee.RAW_access_immutable { aadBuff in
			try CountedNonce(counter: counter).RAW_access_immutable(UnsafeRawBufferPointer.self) { 
				try context.decrypt(tag:tag, nonce:$0.load(fromByteOffset:0, as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		return A(RAW_decode:UnsafeRawBufferPointer(start:plainText.baseAddress!, count:cipherTextBuff.count))!
	}
}

internal func aeadDecryptV2<A, D, K, O>(as _:O.Type, key:borrowing K, counter:UInt64, cipherText:borrowing A, aad:consuming D, tag:Tag) throws -> O where A:RAW_accessible, O:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_fixed_type == Key32.RAW_fixed_type {
	var context = withUnsafePointer(to:key) { keyPtr in
		return RAW_chachapoly.Context(key:UnsafeRawBufferPointer(start:UnsafeRawPointer(keyPtr), count:MemoryLayout<K.RAW_fixed_type>.size))!
	}
	return try cipherText.RAW_access_immutable { cipherTextBuff in
		let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherTextBuff.count)
		defer { plainText.deallocate() }
		try aad.RAW_access_immutable { aadBuff in
			try CountedNonce(counter: counter).RAW_access_immutable(UnsafeRawBufferPointer.self) { 
				try context.decrypt(tag:tag, nonce:$0.load(fromByteOffset:0, as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		return O(RAW_decode:UnsafeRawBufferPointer(start:plainText.baseAddress!, count:cipherTextBuff.count))!
	}
}

internal func aeadDecryptV3(plainText:UnsafeMutableRawPointer, key:UnsafeRawBufferPointer, counter:UInt64, cipherText cipherTextBuff:UnsafeRawBufferPointer, aad aadBuff:UnsafeRawBufferPointer, tag:UnsafeRawPointer) throws {
	var context = RAW_chachapoly.Context(key:key)!
	try CountedNonce(counter: counter).RAW_access_immutable(UnsafeRawBufferPointer.self) { 
		try context.decrypt(tag:tag, nonce:$0.baseAddress!, associatedData:aadBuff, inputData:cipherTextBuff, output:plainText)
	}
}

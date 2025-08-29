import RAW
import RAW_dh25519
import RAW_chachapoly

internal func aeadEncrypt<A, D, K>(key:UnsafePointer<K>, counter:UInt64, text:UnsafePointer<A>, aad:UnsafePointer<D>) throws -> (A, Tag) where A:RAW_accessible, A:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key32.RAW_staticbuff_storetype {
	var context = RAW_chachapoly.Context(key:key)
	return try text.pointee.RAW_access { textBuff in
		let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:textBuff.count)
		defer { cipherText.deallocate() }
		let tag = try aad.pointee.RAW_access { aadBuff in
			return try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
		return (A(RAW_decode:cipherText.baseAddress!, count: textBuff.count)!, tag)
	}
}

internal func aeadEncryptV2<A, D, K, O>(as _:O.Type = A.self, key:borrowing K, counter:UInt64, text:borrowing A, aad:UnsafePointer<D>) throws -> (O, Tag) where A:RAW_staticbuff, O:RAW_staticbuff, D:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key32.RAW_staticbuff_storetype, A.RAW_staticbuff_storetype == O.RAW_staticbuff_storetype {
	var context = RAW_chachapoly.Context(key:key)
	return try text.RAW_access { textBuff in
		let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:textBuff.count)
		defer { cipherText.deallocate() }
		let tag = try aad.pointee.RAW_access { aadBuff in
			return try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
		return (O(RAW_decode:cipherText.baseAddress!, count: textBuff.count)!, tag)
	}
}

internal func aeadDecrypt<A, D, K>(key:UnsafePointer<K>, counter:UInt64, cipherText:UnsafePointer<A>, aad:UnsafePointer<D>, tag:Tag) throws -> A where A:RAW_accessible, A:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key32.RAW_staticbuff_storetype {
	var context = RAW_chachapoly.Context(key:key)
	return try cipherText.pointee.RAW_access { cipherTextBuff in
		let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherTextBuff.count)
		defer { plainText.deallocate() }
		try aad.pointee.RAW_access { aadBuff in
			try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		return A(RAW_decode:plainText.baseAddress!, count:cipherTextBuff.count)!
	}
}

internal func aeadDecryptV2<A, D, K, O>(as _:O.Type, key:borrowing K, counter:UInt64, cipherText:borrowing A, aad:consuming D, tag:Tag) throws -> O where A:RAW_accessible, O:RAW_decodable, D:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key32.RAW_staticbuff_storetype {
	var context = RAW_chachapoly.Context(key:key)
	return try cipherText.RAW_access { cipherTextBuff in
		let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherTextBuff.count)
		defer { plainText.deallocate() }
		try aad.RAW_access { aadBuff in
			try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		return O(RAW_decode:plainText.baseAddress!, count:cipherTextBuff.count)!
	}
}

internal func aeadDecryptV3(into plaintextPtr:UnsafeMutablePointer<UInt8>, key:UnsafeBufferPointer<UInt8>, counter:UInt64, cipherText cipherTextBuff:UnsafeBufferPointer<UInt8>, aad aadBuff:UnsafeBufferPointer<UInt8>, tag:Tag) throws {
	var context = RAW_chachapoly.Context(key:key)!
	try CountedNonce(counter: counter).RAW_access_staticbuff { 
		try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plaintextPtr)
	}
}
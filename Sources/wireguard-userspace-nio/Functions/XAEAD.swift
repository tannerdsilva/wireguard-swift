import RAW
import RAW_xchachapoly

internal func xaead(key:consuming RAW_xchachapoly.Key, counter:UInt64, text:borrowing [UInt8], aad:consuming [UInt8]) throws -> ([UInt8], Tag) {
	var ourTag:Tag = Tag()
	return (try [UInt8](unsafeUninitializedCapacity: text.count) { cipherText, initializedCount in
		var context = RAW_xchachapoly.Context(key:key)
		try text.RAW_access { textBuff in
			try aad.RAW_access { aadBuff in
				try CountedNonce(counter:counter).RAW_access_staticbuff { 
					ourTag = try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
				}
			}
		}
		initializedCount = cipherText.count
	}, ourTag)
}

internal func xaeadDecrypt(key:consuming RAW_xchachapoly.Key, counter:UInt64, cipherText:consuming [UInt8], aad:consuming [UInt8], tag:consuming Tag) throws -> [UInt8] {
	return try cipherText.withUnsafeBufferPointer { cipherTextBuff in
		return try [UInt8](unsafeUninitializedCapacity:cipherTextBuff.count) { plainText, initializedCount in
			var context = RAW_xchachapoly.Context(key:key)
			try aad.RAW_access { aadBuff in
				try CountedNonce(counter:counter).RAW_access_staticbuff { 
					try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
				}
			}
			initializedCount = cipherTextBuff.count
		}
	}
}
import RAW
import RAW_xchachapoly

internal func xaead(key:RAW_xchachapoly.Key, counter:UInt64, text:borrowing [UInt8], aad:consuming [UInt8]) throws -> ([UInt8], Tag) {
	let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:text.count)
	defer { cipherText.deallocate() }
	var context = RAW_xchachapoly.Context(key:key)
	let ourTag = try text.RAW_access { textBuff in
		return try aad.RAW_access { aadBuff in
			return try CountedNonce(counter:counter).RAW_access_staticbuff { 
				try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
	}
	return (Array(cipherText), ourTag)
}

internal func xaeadDecrypt(key:RAW_xchachapoly.Key, counter:UInt64, cipherText:borrowing [UInt8], aad:consuming [UInt8], tag:consuming Tag) throws -> [UInt8] {
	let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherText.count)
	defer { plainText.deallocate() }
	var context = RAW_xchachapoly.Context(key:key)
	try cipherText.RAW_access { cipherTextBuff in
		try aad.RAW_access { aadBuff in
			try CountedNonce(counter:counter).RAW_access_staticbuff { 
				try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
	}
	return Array(plainText)
}
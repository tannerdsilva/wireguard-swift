import RAW
import RAW_xchachapoly

internal func xaead(key:RAW_xchachapoly.Key, nonce:Nonce, text: Result16, aad:Result16) throws -> ([UInt8], Tag) {
	var ourTag:Tag = Tag()
	return (try [UInt8](unsafeUninitializedCapacity: 16) { cipherText, initializedCount in
		var context = RAW_xchachapoly.Context(key:key)
		try text.RAW_access { textBuff in
			try aad.RAW_access { aadBuff in
				ourTag = try context.encrypt(nonce:nonce, associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
		initializedCount = cipherText.count
	}, ourTag)
}

internal func xaeadDecrypt(key:RAW_xchachapoly.Key, nonce:Nonce, cipherText: Result16, aad:Result16, tag:consuming Tag) throws -> [UInt8] {
	return try [UInt8](unsafeUninitializedCapacity: 16) { plainText, initializedCount in
		var context = RAW_xchachapoly.Context(key:key)
		try cipherText.RAW_access { cipherTextBuff in
			try aad.RAW_access { aadBuff in
				try context.decrypt(tag:tag, nonce:nonce, associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		initializedCount = 16
	}
}

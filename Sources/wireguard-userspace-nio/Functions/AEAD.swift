import RAW
import RAW_dh25519
import RAW_chachapoly

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:false)
internal struct Zeros:Sendable {
	internal init() {
		self.init(RAW_native:0)
	}
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:false)
internal struct Counter:Sendable {}

@RAW_staticbuff(concat:Zeros.self, Counter.self)
internal struct CountedNonce:Sendable {
	internal let zeros:Zeros
	internal let counter:Counter
	internal init(counter:UInt64) {
		self.zeros = Zeros()
		self.counter = Counter(RAW_native:counter)
	}
}

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

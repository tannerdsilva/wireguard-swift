import RAW
import RAW_dh25519
import RAW_base64

extension PrivateKey:@retroactive CustomDebugStringConvertible {
	public var debugDescription: String {
		return "\(String(RAW_base64.encode(self)))"
	}
}

extension PublicKey:@retroactive CustomDebugStringConvertible {
	public var debugDescription: String {
		return "\(String(RAW_base64.encode(self)))"
	}
}

public func dhGenerate() throws -> (PublicKey, PrivateKey) {
	return withUnsafePointer(to:try PrivateKey()) { privateKeyPointer in
		return (PublicKey(privateKey:privateKeyPointer), privateKeyPointer.pointee)
	}
}

internal func dhKeyExchange(privateKey:UnsafePointer<PrivateKey>, publicKey:UnsafePointer<PublicKey>) throws -> SharedKey {
	return SharedKey.compute(privateKey: privateKey, publicKey: publicKey)
}

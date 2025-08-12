import RAW
import RAW_dh25519

public func dhGenerate() throws -> (PublicKey, PrivateKey) {
	return withUnsafePointer(to:try PrivateKey()) { privateKeyPointer in
		return (PublicKey(privateKey:privateKeyPointer), privateKeyPointer.pointee)
	}
}

public func dhKeyExchange(privateKey:UnsafePointer<PrivateKey>, publicKey:UnsafePointer<PublicKey>) throws -> SharedKey {
	return SharedKey.compute(privateKey: privateKey, publicKey: publicKey)
}

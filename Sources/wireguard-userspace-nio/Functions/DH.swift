import RAW
import RAW_dh25519

public func dhGenerate() throws -> (PublicKey, PrivateKey) {
	var privateKey = try PrivateKey()
	let publicKey = PublicKey(&privateKey)
	return (publicKey, privateKey)
}

internal func dhKeyExchange(privateKey:UnsafePointer<PrivateKey>, publicKey:UnsafePointer<PublicKey>) throws -> SharedKey {
	return SharedKey.compute(privateKey: privateKey, publicKey: publicKey)
}

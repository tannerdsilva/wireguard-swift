import RAW
import RAW_dh25519

public func dhGenerate() throws -> (PublicKey, MemoryGuarded<PrivateKey>) {
	let pk = try MemoryGuarded<PrivateKey>.new()
	return (PublicKey(privateKey:pk), pk)
}

public func dhKeyExchange(privateKey:MemoryGuarded<PrivateKey>, publicKey:PublicKey) throws -> MemoryGuarded<SharedKey> {
	return try .compute(privateKey:privateKey, publicKey: publicKey)
}

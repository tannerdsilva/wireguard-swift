import RAW
import RAW_dh25519

/// Generates a new `PublicKey` and `MemoryGuarded<PrivateKey>`.
public func dhGenerate() throws -> (PublicKey, MemoryGuarded<PrivateKey>) {
	let pk = try MemoryGuarded<PrivateKey>.new()
	return (PublicKey(privateKey:pk), pk)
}

/// Generates the `MemoryGuarded<SharedKey>` for a given `PrivateKey` and `PublicKey`.
public func dhKeyExchange(privateKey:MemoryGuarded<PrivateKey>, publicKey:PublicKey) throws -> MemoryGuarded<SharedKey> {
	return try .compute(privateKey:privateKey, publicKey: publicKey)
}

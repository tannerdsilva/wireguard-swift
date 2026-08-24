import RAW_dh25519
import RAW_base64

extension PrivateKey:@retroactive CustomDebugStringConvertible {
	/// A base64-encoded representation of the private key.
	public var debugDescription: String {
		return "\(String(RAW_base64.encode(self)))"
	}
}

extension PublicKey:@retroactive CustomDebugStringConvertible {
	/// A base64-encoded representation of the public key.
	public var debugDescription: String {
		return "\(String(RAW_base64.encode(self)))"
	}
}

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
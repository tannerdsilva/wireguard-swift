import RAW
import RAW_dh25519
import RAW_base64
import ArgumentParser

extension RAW_dh25519.PublicKey:@retroactive ExpressibleByArgument {
	public init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self = RAW_dh25519.PublicKey(RAW_staticbuff:bytes)
	}
}

extension MemoryGuarded<RAW_dh25519.PrivateKey>:@retroactive ExpressibleByArgument {
	public convenience init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self.init(RAW_decode:bytes, count:32)
	}
}


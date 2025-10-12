import RAW
import RAW_dh25519
import RAW_base64
import ArgumentParser
import bedrock_ip

struct Peer : ExpressibleByArgument {
	var port:Int
	var publicKey:RAW_dh25519.PublicKey
	
	init?(argument:String) {
		let parts = argument.split(separator: ":", maxSplits: 1).map(String.init)
		guard parts.count == 2,
			  let port = Int(parts[0]) else {
			return nil
		}
		self.port = port
		let rawBytes = try? RAW_base64.decode(parts[1])
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self.publicKey = RAW_dh25519.PublicKey(RAW_staticbuff:bytes)
	}
}

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

extension Address:@retroactive ExpressibleByArgument {}


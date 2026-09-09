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
		self.publicKey = bytes.withUnsafeBytes { raw in
			return RAW_dh25519.PublicKey(RAW_decode:raw)!
		}
	}
}

extension RAW_dh25519.PublicKey:@retroactive ExpressibleByArgument {
	public init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self = bytes.withUnsafeBytes { raw in
			return RAW_dh25519.PublicKey(RAW_decode:raw)!
		}
	}
}

extension MemoryGuarded<RAW_dh25519.PrivateKey>:@retroactive ExpressibleByArgument {
	public convenience init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		let storage = UnsafeMutableRawBufferPointer.allocate(byteCount:bytes.count, alignment:1)
		defer { storage.deallocate() }
		bytes.withUnsafeBytes { raw in
			storage.baseAddress!.copyMemory(from:raw.baseAddress!, byteCount:bytes.count)
		}
		self.init(RAW_decode:UnsafeRawBufferPointer(start:storage.baseAddress, count:bytes.count))
	}
}

extension Address:@retroactive ExpressibleByArgument {}

import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension Message:RAW_encodable {
    public func RAW_encode(count: inout RAW.size_t) {
        switch self {
            case .initiation(let payload):
                payload.RAW_encode(count: &count)
            case .response(let payload):
                payload.RAW_encode(count: &count)
            case .cookie(let payload):
                payload.RAW_encode(count: &count)
            case .data(let payload):
                fatalError("do not use RAW_encodable protocol on Message.Data")
        }
    }

	public func RAW_encode(dest:UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		switch self {
			case .initiation(let payload):
				return payload.RAW_encode(dest:dest)
			case .response(let payload):
				return payload.RAW_encode(dest:dest)
			case .cookie(let payload):
				return payload.RAW_encode(dest:dest)
			case .data(let payload):
				fatalError("do not use RAW_encodable protocol on Message.Data")
		}
	}
}
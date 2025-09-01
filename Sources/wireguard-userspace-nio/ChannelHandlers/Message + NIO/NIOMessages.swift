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

extension Message {
	internal enum NIO {
		case initiation(Message.Initiation.Payload.Authenticated)
		case response(Message.Response.Payload.Authenticated)
		case cookie(Message.Cookie.Payload)
		case data(Message.Data.Header, ByteBufferView)
	}
}

extension Message.Data.Payload {
	internal static func forge(receiverIndex:PeerIndex, nonce:inout Counter, transportKey:Result.Bytes32, plainText:inout ByteBuffer, output:UnsafeMutableRawPointer) throws -> Int {
		let unpaddedLength = plainText.readableBytes
		let messagePadding = Message.Data.Payload.paddedLength(count:unpaddedLength) - unpaddedLength
		plainText.writeBytes([UInt8](repeating:0, count:messagePadding))
		let wroteBytes = try plainText.withUnsafeReadableBytes { paddedPlaintext in
			return try forge(receiverIndex:receiverIndex, nonce:&nonce, transportKey:transportKey, paddedPlainText:paddedPlaintext, output:output)
		}
		return wroteBytes
	}
}
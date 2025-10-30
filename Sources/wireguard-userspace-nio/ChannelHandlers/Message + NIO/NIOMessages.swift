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
            case .data(_):
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
			case .data(_):
				fatalError("do not use RAW_encodable protocol on Message.Data")
		}
		
	}
}

extension Message {
	/// a variant of the Message enum that is suitable for use in NIO pipelines. this symbol exists to minimize the number of copies of data that need to be made when processing packets in the NIO pipeline.
	public enum NIO {
		/// identical to `Message.Initiation.Payload.Authenticated`
		case initiation(Message.Initiation.Payload.Authenticated)
		/// identical to `Message.Response.Payload.Authenticated`
		case response(Message.Response.Payload.Authenticated)
		/// identical to `Message.Cookie.Payload`
		case cookie(Message.Cookie.Payload)
		/// a special variant of data that is based in ByteBufferView instead of a raw pointer and length.
		case data(recipientIndex:PeerIndex, counter:Counter, payload:ByteBufferView)
	}
}

extension Message.Data.Payload {
	/// forges a new data payload packet into the provided output buffer.
	/// - parameters:
	///   - receiverIndex: the peer index of the recipient of this packet.
	///   - nonce: the counter value to use for this packet. this value will be incremented by 1 if the packet is successfully forged.
	///   - transportKey: the symmetric transport key to use for this packet.
	///   - plainText: the plaintext data to encrypt and include in this packet. this buffer will be padded to the next 16-byte boundary as required by the protocol.
	///   - output: a pointer to a buffer that is at least `MemoryLayout<Message.Data.Payload>.size + plainText.paddedLength` bytes in size.
	/// - returns: the number of bytes written to the output buffer.
	/// - throws: an error if the packet could not be forged.
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

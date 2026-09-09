import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension Message:RAW_encodable {
	/// Reports the number of bytes required to encode the message.
    public func RAW_encode(count: inout Int) {
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

	/// Encodes the message into `destination` and returns a pointer advanced past the
	/// written bytes.
	public func RAW_encode(_: UnsafeMutableRawPointer.Type, destination: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
		switch self {
			case .initiation(let payload):
				return payload.RAW_encode(UnsafeMutableRawPointer.self, destination:destination)
			case .response(let payload):
				return payload.RAW_encode(UnsafeMutableRawPointer.self, destination:destination)
			case .cookie(let payload):
				return payload.RAW_encode(UnsafeMutableRawPointer.self, destination:destination)
			case .data(_):
				fatalError("do not use RAW_encodable protocol on Message.Data")
		}
		
	}
}

extension Message {
	/// A variant of the `Message` enum suitable for use in NIO pipelines. This
	/// symbol exists to minimize the number of copies of data that need to be
	/// made when processing packets in the NIO pipeline.
	public enum NIO {
		/// Identical to `Message.Initiation.Payload.Authenticated`.
		case initiation(Message.Initiation.Payload.Authenticated)
		/// Identical to `Message.Response.Payload.Authenticated`.
		case response(Message.Response.Payload.Authenticated)
		/// Identical to `Message.Cookie.Payload`.
		case cookie(Message.Cookie.Payload)
		/// A special variant of data backed by a `ByteBufferView` instead of a raw
		/// pointer and length.
		case data(recipientIndex:PeerIndex, counter:Counter, payload:ByteBufferView)
	}
}

extension Message.Data.Payload {
	/// Forges a new data payload packet into the provided output buffer.
	/// - Parameters:
	///   - receiverIndex: The peer index of the recipient of this packet.
	///   - nonce: The counter value to use for this packet. This value is incremented by 1 if the packet is successfully forged.
	///   - transportKey: The symmetric transport key to use for this packet.
	///   - plainText: The plaintext data to encrypt and include in this packet. This buffer is padded to the next 16-byte boundary as required by the protocol.
	///   - output: A pointer to a buffer that is at least `MemoryLayout<Message.Data.Payload>.size + plainText.paddedLength` bytes in size.
	/// - Returns: The number of bytes written to the output buffer.
	/// - Throws: An error if the packet could not be forged.
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

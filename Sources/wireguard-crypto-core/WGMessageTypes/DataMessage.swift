import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64
import func Foundation.ceil

extension Message {
	/// A transport data message, used to carry encrypted application data.
	public struct Data {
		/// The header of a data message. "Header" is used loosely here, since it also
		/// spans the encryption tag, which encodes at the end of the data sequence.
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Counter.self)
		public struct Header:Sendable {
			/// The message type header (type and reserved bytes).
			public let typeHeader:TypeHeading
			/// The peer index of the recipient of the data payload.
			public let recipientIndex:PeerIndex
			/// The packet counter.
			public let counter:Counter
			/// Creates a new data message header.
			public init(typeHeader:TypeHeading = 0x4, recipientIndex:PeerIndex, counter:Counter) {
				self.typeHeader = typeHeader
				self.recipientIndex = recipientIndex
				self.counter = counter
			}
		}
		
		/// The serialized contents of a data message.
		public struct Payload:Sendable, RAW_encodable, RAW_decodable {
			/// The message header.
			public let header:Header
			/// The encrypted data payload.
			public let data:[UInt8]
			/// The authentication tag appended to the ciphertext.
			public let tag:Tag

			/// Returns the length of `count` rounded up to the next multiple of 16.
			public static func paddedLength(count:Int) -> Int {
				return 16 * Int(ceil(Double(count) / 16.0))
			}

			/// Attempts to decode a data message payload from the given raw bytes.
			public init?(RAW_decode input:UnsafeRawBufferPointer) {
				guard input.count >= MemoryLayout<Header>.size + MemoryLayout<Tag>.size else { return nil }
				var seekPtr = input.baseAddress!
				let typeHeading = TypeHeading(RAW_staticbuff_seeking:&seekPtr)
				let recipientIndex = PeerIndex(RAW_staticbuff_seeking:&seekPtr)
				let counter = Counter(RAW_staticbuff_seeking:&seekPtr)
				let dataCount = input.count - (MemoryLayout<Header>.size + MemoryLayout<Tag>.size)
				var tagSeekPtr = seekPtr.advanced(by:dataCount)
				let packetTag = Tag(RAW_staticbuff_seeking:&tagSeekPtr)
				self.header = Header(typeHeader:typeHeading, recipientIndex:recipientIndex, counter:counter)
				self.data = [UInt8](RAW_decode:UnsafeRawBufferPointer(start:seekPtr, count:dataCount))
				self.tag = packetTag
			}
			
			/// Reports the number of bytes required to encode the payload, including padding and tag.
			public func RAW_encode(count: inout Int) {
				count = MemoryLayout<Header>.size + Self.paddedLength(count:data.count) + MemoryLayout<Tag>.size
			}
			
			/// Encodes the payload into `destination` and returns a pointer advanced past the written bytes.
			public func RAW_encode(_: UnsafeMutableRawPointer.Type, destination: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
				var dest = header.typeHeader.RAW_encode(UnsafeMutableRawPointer.self, destination:destination)
				dest = header.recipientIndex.RAW_encode(UnsafeMutableRawPointer.self, destination:dest)
				dest = header.counter.RAW_encode(UnsafeMutableRawPointer.self, destination:dest)
				dest = data.RAW_encode(UnsafeMutableRawPointer.self, destination:dest)
				dest = tag.RAW_encode(UnsafeMutableRawPointer.self, destination:dest)
				return dest
			}

			private init(header:Header, data:[UInt8], tag:Tag) {
				self.header = header
				self.data = data
				self.tag = tag
			}

			/// Decrypts the payload using the given transport key.
			/// - Parameter transportKey: The session transport key.
			/// - Returns: The decrypted plaintext.
			/// - Throws: If decryption fails.
			public borrowing func decrypt(transportKey:borrowing Result.Bytes32) throws -> [UInt8] {
				return try aeadDecryptV2(as:[UInt8].self, key:transportKey, counter:header.counter.RAW_native(), cipherText:data, aad:[], tag:tag)
			}

			/// Decrypts a data message from caller-owned buffers into `plainText`.
			/// - Parameters:
			///   - transportKey: The session transport key.
			///   - counter: The packet counter.
			///   - input: The ciphertext, starting at the message header.
			///   - tag: A pointer to the authentication tag.
			///   - aad: Associated data for the AEAD (unused).
			///   - output: A buffer at least as large as the plaintext; the decrypted
			///     bytes are written here.
			/// - Throws: If decryption fails.
			public static func decrypt(transportKey:borrowing Result.Bytes32, counter:Counter, cipherText input:UnsafeRawBufferPointer, tag:UnsafeRawPointer, aad:UnsafeRawBufferPointer, plainText output:UnsafeMutableRawPointer) throws {
				try transportKey.RAW_access_immutable(UnsafeRawBufferPointer.self) { transportKeyPtr in
					try aeadDecryptV3(plainText:output, key:transportKeyPtr, counter:counter.RAW_native(), cipherText:input, aad:UnsafeRawBufferPointer(start:tag, count:0), tag:tag)
				}
			}

			/// Builds a data message payload from plaintext, zero-padded and encrypted with the given transport key.
			/// - Parameters:
			///   - receiverIndex: The peer index of the recipient.
			///   - nonce: The packet counter, incremented after forging.
			///   - transportKey: The session transport key.
			///   - plainText: The plaintext to encrypt.
			/// - Returns: The forged data message payload.
			/// - Throws: If encryption fails.
			public static func forge(receiverIndex:PeerIndex, nonce:inout Counter, transportKey:Result.Bytes32, plainText:[UInt8]) throws -> Self {
				// step 1: P := P || 0... Zero Padding the Packet
				let pLength:Int = plainText.count
				let zeros = [UInt8](repeating: 0, count:Self.paddedLength(count:pLength) - pLength)
				var joined = plainText + zeros
				// step 2: msg.counter = nonce
				let msgCounter = nonce
				// step 3: msg.packet := AEAD(Tm, Nm, P, e)
				var e:[UInt8] = []
				let (packet, packetTag) = try withUnsafePointer(to:transportKey) { transportKey in
					try aeadEncrypt(key: transportKey, counter:nonce.RAW_native(), text:&joined, aad: &e)
				}
				// step 4: nonce := nonce + 1
				nonce += 1
				return Self(header:Header(recipientIndex:receiverIndex, counter:msgCounter), data:packet, tag:packetTag)
			}

			/// Forges a data message into a caller-owned output buffer, encrypting in place.
			/// - Parameters:
			///   - receiverIndex: The peer index of the recipient.
			///   - nonce: The packet counter, incremented after forging.
			///   - transportKey: The session transport key.
			///   - paddedPlainText: The plaintext, zero-padded to a multiple of 16.
			///   - output: The output buffer; must have space for header + ciphertext + tag.
			/// - Returns: The total number of bytes written to `output`.
			/// - Throws: If encryption fails.
			public static func forge(receiverIndex:PeerIndex, nonce:inout Counter, transportKey:Result.Bytes32, paddedPlainText:UnsafeRawBufferPointer, output:UnsafeMutableRawPointer) throws -> Int {
				// step 1: P := P || 0... Zero Padding the Packet
				let fullPacketLength = MemoryLayout<Header>.size + paddedPlainText.count + MemoryLayout<Tag>.size
				// write the zero length region
				let msgCounter = nonce
				let buildHeader = Header(recipientIndex:receiverIndex, counter:msgCounter)

				// step 3: msg.packet := AEAD(Tm, Nm, P, e)
				let outputDelta = buildHeader.RAW_encode(dest:output.assumingMemoryBound(to:UInt8.self))
				let tagStart = outputDelta + paddedPlainText.count
				_ = UnsafeMutableRawPointer(tagStart).assumingMemoryBound(to:Tag.self)
				try transportKey.RAW_access_immutable(UnsafeRawBufferPointer.self) { tsKeyPtr in
					try aeadEncryptV3(plaintext:paddedPlainText, key:tsKeyPtr, counter:nonce.RAW_native(), cipherText:outputDelta, aad:UnsafeRawBufferPointer(start:outputDelta, count:0), tag:tagStart)
				}
				
				// step 4: nonce := nonce + 1
				nonce += 1
				let tagEnd = tagStart + MemoryLayout<Tag>.size
				#if DEBUG
				guard tagEnd == output.advanced(by:fullPacketLength).assumingMemoryBound(to:UInt8.self) else {
					fatalError("tag exceeds output buffer. this is a critical internal error. \(#file):\(#line)")
				}
				#endif
				return fullPacketLength
			}
		}
	}
}

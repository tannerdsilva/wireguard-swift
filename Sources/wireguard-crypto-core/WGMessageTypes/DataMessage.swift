import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64
import func Foundation.ceil

// legacy support for DataMessage
@available(*, deprecated, renamed: "Message.Data")
public typealias DataMessage = Message.Data
extension Message.Data {
	@available(*, deprecated, renamed: "Payload")
	public typealias DataPayload = Payload
}

// legay support for payload stored variable
extension Message.Data.Payload {
	@available(*, deprecated, renamed: "header")
	public var payload:Message.Data.Header {
		return header
	}
}

extension Message.Data.Header {
	/// responder's peer index (I_r)
	@available(*, deprecated, renamed:"recipientIndex")
	public var receiverIndex:PeerIndex {
		return recipientIndex
	}
}

extension Message {
	public struct Data {
		/// the header that is used for data messages in wireguard. in this case, header is a loosely used term, as it also includes the encryption tag "tail" which encodes at the end of the data sequence as opposed to before.
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Counter.self)
		public struct Header:Sendable {
			/// message type (type and reserved)
			public let typeHeader:TypeHeading
			/// peer index of the recipient of the data payload
			public let recipientIndex:PeerIndex
			/// packet counter key
			public let counter:Counter
			/// initializes a new HandshakeResponseMessage
			public init(typeHeader:TypeHeading = 0x4, recipientIndex:PeerIndex, counter:Counter) {
				self.typeHeader = typeHeader
				self.recipientIndex = recipientIndex
				self.counter = counter
			}
		}
		
		public struct Payload:Sendable, RAW_encodable, RAW_decodable {
			public let header:Header
			public let data:[UInt8]
			public let tag:Tag

			public static func paddedLength(count:Int) -> Int {
				return 16 * Int(ceil(Double(count) / 16.0))
			}

			public init?(RAW_decode inputPtr:consuming UnsafeRawPointer, count:size_t) {
				guard count >= MemoryLayout<Header>.size + MemoryLayout<Tag>.size else { return nil }
				(header, data, tag) = withUnsafeMutablePointer(to:&inputPtr) { RAW_decode in
					let typeHeading = TypeHeading(RAW_staticbuff_seeking:RAW_decode)
					let recipientIndex = PeerIndex(RAW_staticbuff_seeking:RAW_decode)
					let counter = Counter(RAW_staticbuff_seeking:RAW_decode)
					let dataCount = count - (MemoryLayout<Header>.size + MemoryLayout<Tag>.size)
					let packetTag = Tag(RAW_staticbuff:RAW_decode.pointee.advanced(by:dataCount))
					return (Header(typeHeader:typeHeading, recipientIndex:recipientIndex, counter:counter), [UInt8](RAW_decode:RAW_decode.pointee, count:dataCount), packetTag)
				}
			}
			
			public func RAW_encode(count: inout RAW.size_t) {
				count = MemoryLayout<Header>.size + data.count + MemoryLayout<Tag>.size
			}
			
			public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
				var dest = header.typeHeader.RAW_encode(dest:dest)
				dest = header.receiverIndex.RAW_encode(dest:dest)
				dest = header.counter.RAW_encode(dest:dest)
				dest = data.RAW_encode(dest:dest)
				dest = tag.RAW_encode(dest:dest)
				return dest
			}

			private init(header:Header, data:[UInt8], tag:Tag) {
				self.header = header
				self.data = data
				self.tag = tag
			}

			public borrowing func decrypt(transportKey:borrowing Result.Bytes32) throws -> [UInt8] {
				return try aeadDecryptV2(as:[UInt8].self, key:transportKey, counter:header.counter.RAW_native(), cipherText:data, aad:[], tag:tag)
			}

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

			public static func forge(receiverIndex:PeerIndex, nonce:inout Counter, transportKey:Result.Bytes32, paddedPlainText:UnsafeRawBufferPointer, output:UnsafeMutableRawPointer) throws -> Int {
				// step 1: P := P || 0... Zero Padding the Packet
				let fullPacketLength = MemoryLayout<Header>.size + paddedPlainText.count + MemoryLayout<Tag>.size
				// write the zero length region
				let msgCounter = nonce
				let buildHeader = Header(recipientIndex:receiverIndex, counter:msgCounter)

				// step 3: msg.packet := AEAD(Tm, Nm, P, e)
				let outputDelta = buildHeader.RAW_encode(dest:output.assumingMemoryBound(to:UInt8.self))
				let tagStart = outputDelta + paddedPlainText.count
				let tagAssociatedData = UnsafeMutableRawPointer(tagStart).assumingMemoryBound(to:Tag.self)
				try transportKey.RAW_access_staticbuff { tsKeyPtr in
					try aeadEncryptV3(plaintext:paddedPlainText, key:UnsafeRawBufferPointer(start:tsKeyPtr, count:MemoryLayout<Result.Bytes32>.size), counter:nonce.RAW_native(), cipherText:outputDelta, aad:UnsafeRawBufferPointer(start:outputDelta, count:0), tag:tagStart)
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
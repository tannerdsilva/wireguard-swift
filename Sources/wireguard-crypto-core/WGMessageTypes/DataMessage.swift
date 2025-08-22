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
// legacy support for packetTag stored variable
extension Message.Data.Header {
	@available(*, deprecated, renamed: "tag")
	public var packetTag:Tag {
		return tag
	}
}

extension Message {
	public struct Data {
		public struct Header:Sendable {
			/// message type (type and reserved)
			public let typeHeader:TypeHeading
			/// peer index of the recipient of the data payload
			public let recipientIndex:PeerIndex
			/// responder's peer index (I_r)
			@available(*, deprecated, renamed:"recipientIndex")
			public var receiverIndex:PeerIndex {
				return recipientIndex
			}
			/// packet counter key
			public let counter:Counter
			/// packet tag of message
			public let tag:Tag

			/// initializes a new HandshakeResponseMessage
			fileprivate init(typeHeader:TypeHeading = 0x4, recipientIndex:PeerIndex, counter:Counter, packetTag tag:Tag) {
				self.typeHeader = typeHeader
				self.recipientIndex = recipientIndex
				self.counter = counter
				self.tag = tag
			}
		}
		
		public struct Payload:Sendable, RAW_encodable, RAW_decodable {
			public let header:Header
			public let data:[UInt8]

			public init?(RAW_decode inputPtr:consuming UnsafeRawPointer, count:size_t) {
				guard count >= MemoryLayout<Header>.size else { return nil }
				(header, data) = withUnsafeMutablePointer(to:&inputPtr) { RAW_decode in
					let typeHeading = TypeHeading(RAW_staticbuff_seeking:RAW_decode)
					let recipientIndex = PeerIndex(RAW_staticbuff_seeking:RAW_decode)
					let counter = Counter(RAW_staticbuff_seeking:RAW_decode)
					let dataCount = count - MemoryLayout<Header>.size
					let packetTag = Tag(RAW_staticbuff:RAW_decode.pointee.advanced(by:dataCount))
					return (Header(typeHeader:typeHeading, recipientIndex:recipientIndex, counter:counter, packetTag:packetTag), [UInt8](RAW_decode:RAW_decode.pointee, count:dataCount))
				}
			}
			
			public func RAW_encode(count: inout RAW.size_t) {
				count = MemoryLayout<Header>.size + data.count
			}
			
			public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
				var dest = header.typeHeader.RAW_encode(dest:dest)
				dest = header.receiverIndex.RAW_encode(dest:dest)
				dest = header.counter.RAW_encode(dest:dest)
				dest = data.RAW_encode(dest:dest)
				dest = header.tag.RAW_encode(dest:dest)
				return dest
			}

			private init(header:Header, data:[UInt8]) {
				self.header = header
				self.data = data
			}

			public borrowing func decrypt(transportKey:borrowing Result.Bytes32) throws -> [UInt8] {
				return try aeadDecryptV2(as:[UInt8].self, key:transportKey, counter:header.counter.RAW_native(), cipherText:data, aad:[], tag:header.tag)
			}

			public static func forge(receiverIndex:PeerIndex, nonce:inout Counter, transportKey:Result.Bytes32, plainText:[UInt8]) throws -> Self {
				// step 1: P := P || 0... Zero Padding the Packet
				let pLength:Int = plainText.count
				let zeros = [UInt8](repeating: 0, count:16 * Int(ceil(Double(pLength)/16.0)) - pLength)
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
				return Self(header:Header(recipientIndex:receiverIndex, counter:msgCounter, packetTag:packetTag), data:packet)
			}
		}
	}
}

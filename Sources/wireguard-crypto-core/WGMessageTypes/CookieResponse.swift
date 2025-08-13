// yummmm, cookie
import RAW
import RAW_dh25519
import struct RAW_chachapoly.Tag
import RAW_xchachapoly
import RAW_base64
import bedrock_ip // replacement target for NIO.SocketAddress

@available(*, deprecated, renamed: "Message.Cookie")
public typealias CookieReplyMessage = Message.Cookie

extension Message {
	public struct Cookie {
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Nonce.self, Result.Bytes16.self, Tag.self)
		public struct Payload:Sendable, Sequence {
			/// message type (type and reserved)
			public let typeHeader:TypeHeading
			/// responder's peer index (I_r)
			public let receiverIndex:PeerIndex
			/// random nonce
			public let nonce:Nonce
			/// cookie message
			public let cookieMsg:Result.Bytes16
			/// cookie tag
			public let cookieTag:Tag

			/// initializes a new HandshakeResponseMessage
			fileprivate init(receiverIndex:PeerIndex, nonce:Nonce, cookieMsg:Result.Bytes16, cookieTag:Tag) {
				self.typeHeader = 0x3
				self.receiverIndex = receiverIndex
				self.nonce = nonce
				self.cookieMsg = cookieMsg
				self.cookieTag = cookieTag
			}

			public static func forgeNoNIO(receiverPeerIndex:PeerIndex, k:RAW_xchachapoly.Key, r:Result.Bytes8, endpoint:Endpoint, m:Result.Bytes16) throws -> Self {
				let T:Result.Bytes16
				switch endpoint {
					case .v4(let v4ep):
						T = try wgMACv2(key:r, data:v4ep)
					case .v6(let v6ep):
						T = try wgMACv2(key:r, data:v6ep)
				}
				let nonce = try generateSecureRandomBytes(as:Nonce.self)
				let (cookieMsg, cookieTag) = try xaead(key: k, nonce: nonce, text: T, aad:m)
				return Self(receiverIndex: receiverPeerIndex, nonce: nonce, cookieMsg:Result.Bytes16(RAW_staticbuff:cookieMsg), cookieTag: cookieTag)
			}
		}
	}
}

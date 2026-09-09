// yummmm, cookie
import RAW
import RAW_dh25519
import struct RAW_chachapoly.Tag
import RAW_xchachapoly
import RAW_base64
import bedrock_ip // replacement target for NIO.SocketAddress

/// A deprecated alias for `Message.Cookie`.
@available(*, deprecated, renamed: "Message.Cookie")
public typealias CookieReplyMessage = Message.Cookie

extension Message {
	/// A cookie reply message, sent by under-load responders to authenticate handshakes.
	public struct Cookie {
		/// The serialized contents of a cookie reply message.
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Nonce.self, Result.Bytes16.self, Tag.self)
		public struct Payload:Sendable {
			/// The message type header (type and reserved bytes).
			public let typeHeader:TypeHeading
			/// The responder's peer index (I_r).
			public let initiatorIndex:PeerIndex
			/// A random nonce.
			public let nonce:Nonce
			/// The encrypted cookie message.
			public let cookieMsg:Result.Bytes16
			/// The authentication tag for the cookie message.
			public let cookieTag:Tag

			/// Creates a new cookie reply payload.
			fileprivate init(initiatorIndex:PeerIndex, nonce:Nonce, cookieMsg:Result.Bytes16, cookieTag:Tag) {
				self.typeHeader = 0x3
				self.initiatorIndex = initiatorIndex
				self.nonce = nonce
				self.cookieMsg = cookieMsg
				self.cookieTag = cookieTag
			}

			/// Builds a cookie reply payload for the given initiator, cookie key, and source endpoint.
			/// - Parameters:
			///   - initiatorsPeerIndex: The initiator's peer index (I_r) to echo back.
			///   - k: The responder's cookie key.
			///   - r: The responder's per-peer cookie secret.
			///   - endpoint: The source endpoint of the message being answered.
			///   - m: The message being answered, used as AEAD associated data.
			/// - Returns: The forged cookie reply payload.
			/// - Throws: If key derivation or encryption fails.
			public static func forge(initiatorsPeerIndex:PeerIndex, k:RAW_xchachapoly.Key, r:Result.Bytes8, endpoint:Endpoint, m:Result.Bytes16) throws -> Self {
				let T:Result.Bytes16
				switch endpoint {
					case .v4(let v4ep):
						T = try wgMAC(key:r, data:v4ep)
					case .v6(let v6ep):
						T = try wgMAC(key:r, data:v6ep)
				}
				let nonceBytes = try generateSecureRandomBytes(count:MemoryLayout<Nonce.RAW_fixed_type>.size)
			let nonce = nonceBytes.withUnsafeBytes { raw in
				return Nonce(RAW_decode:raw)!
			}
				let (cookieMsg, cookieTag) = try xaead(key: k, nonce: nonce, text: T, aad:m)
				let cookieBytes = cookieMsg.withUnsafeBytes { raw in
				return Result.Bytes16(RAW_decode:raw)!
			}
			return Self(initiatorIndex: initiatorsPeerIndex, nonce: nonce, cookieMsg: cookieBytes, cookieTag: cookieTag)
			}
		}
	}
}

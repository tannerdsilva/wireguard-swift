// yummmm, cookie
import RAW
import RAW_dh25519
import struct RAW_chachapoly.Tag
import RAW_xchachapoly
import RAW_base64
import bedrock_ip // replacement target for NIO.SocketAddress
import NIO // needs to go away

@available(*, deprecated, renamed: "Message.Cookie")
public typealias CookieReplyMessage = Message.Cookie

extension Message {
	public struct Cookie:Sendable {
		// internal static func forgeCookieReplyV2(receiverPeerIndex:PeerIndex, k:RAW_xchachapoly.Key, R:Result8, A:Address, M:Result16) throws -> Payload {
		// 	var address:[UInt8]
		// 	switch A {
		// 		case .v4(let addr):
		// 			try addr.RAW_access { size_taddr in
						
		// 			}
		// 			address = [UInt8](RAW_decode:, count:size_taddr)

		// 		case .v6(let addr):
		// 			let ipBytes = withUnsafeBytes(of: addr.address.sin6_addr.__u6_addr.__u6_addr8) { Array($0) }
		// 			let portBytes = withUnsafeBytes(of: UInt16(A.port!).bigEndian) { Array($0) }
		// 			address = ipBytes + portBytes
					
		// 		default:
		// 			address = []
		// 	}
		// }
		
		
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Nonce.self, Result16.self, Tag.self)
		public struct Payload:Sendable, Sequence {
			/// message type (type and reserved)
			public let typeHeader:TypeHeading
			/// responder's peer index (I_r)
			public let receiverIndex:PeerIndex
			/// random nonce
			public let nonce:Nonce
			/// cookie message
			public let cookieMsg:Result16
			/// cookie tag
			public let cookieTag:Tag

			/// initializes a new HandshakeResponseMessage
			fileprivate init(receiverIndex:PeerIndex, nonce:Nonce, cookieMsg:Result16, cookieTag:Tag) {
				self.typeHeader = 0x3
				self.receiverIndex = receiverIndex
				self.nonce = nonce
				self.cookieMsg = cookieMsg
				self.cookieTag = cookieTag
			}

			public static func forge(receiverPeerIndex:PeerIndex, k:RAW_xchachapoly.Key , r:Result8, a:NIO.SocketAddress, m:Result16) throws -> Self {
				var address:[UInt8]
				switch a {
					case .v4(let addr):
						let ipBytes = withUnsafeBytes(of: addr.address.sin_addr.s_addr.bigEndian) { Array($0) }
						let portBytes = withUnsafeBytes(of: UInt16(a.port!).bigEndian) { Array($0) }
						address = ipBytes + portBytes
						
					case .v6(let addr):
						let ipBytes = withUnsafeBytes(of: addr.address.sin6_addr.__u6_addr.__u6_addr8) { Array($0) }
						let portBytes = withUnsafeBytes(of: UInt16(a.port!).bigEndian) { Array($0) }
						address = ipBytes + portBytes
						
					default:
						address = []
				}
				let T = try wgMac(key:r, data: address)

				let nonce = try generateSecureRandomBytes(as:Nonce.self)
				
				let (cookieMsg, cookieTag) = try xaead(key: k, nonce: nonce, text: T, aad:m)
		
				
				return Self(receiverIndex: receiverPeerIndex, nonce: nonce, cookieMsg:Result16(RAW_staticbuff:cookieMsg), cookieTag: cookieTag)
			}
		}
	}
}
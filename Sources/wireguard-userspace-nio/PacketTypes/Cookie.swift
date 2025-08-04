// Yummmm, Cookie

import RAW
import RAW_dh25519
import RAW_xchachapoly
import RAW_base64
import NIO

@RAW_staticbuff(bytes: 24)
internal struct Result24:Sendable{}

internal struct CookieReplyMessage:Sendable {
	internal static func forgeCookieReply(receiverPeerIndex:PeerIndex, myStaticPublicKey:PublicKey, R: Result8, A: SocketAddress, M:Result16) throws -> Payload {
		
		var address:String
		switch A {
			case .v4(let addr):
				address = "\(addr.host):\(String(describing: A.port))"
			case .v6(let addr):
				address = "[\(addr.host)]:\(String(describing: A.port))"
			default :
				address = ""
		}
				
		var T = try wgMac(key: R, data: address._base64Decoded())
		
		var nonce = try generateSecureRandomBytes(as:Nonce.self)
		
		var hasher = try WGHasherV2<RAW_xchachapoly.Key>()
		try hasher.update([UInt8]("cookie--".utf8))
		try hasher.update(myStaticPublicKey)
		var k = try hasher.finish()
		let (cookieMsg, cookieTag) = try xaead(key: k, nonce: nonce, text: T, aad: M)
		
		var msg:Result16 = Result16(RAW_staticbuff:cookieMsg)
		
		return Payload(receiverIndex: receiverPeerIndex, nonce: nonce, cookieMsg: msg, cookieTag: cookieTag)
	}
	
	@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Nonce.self, Result16.self, Tag.self)
	internal struct Payload:Sendable {
		/// message type (type and reserved)
		let typeHeader:TypeHeading
		/// responder's peer index (I_r)
		internal let receiverIndex:PeerIndex
		/// random nonce
		internal let nonce:Nonce
		/// cookie message
		internal let cookieMsg:Result16
		/// cookie tag
		internal let cookieTag:Tag

		/// initializes a new HandshakeResponseMessage
		fileprivate init(receiverIndex:PeerIndex, nonce:Nonce, cookieMsg:Result16, cookieTag:Tag) {
			self.typeHeader = 0x3
			self.receiverIndex = receiverIndex
			self.nonce = nonce
			self.cookieMsg = cookieMsg
			self.cookieTag = cookieTag
		}
	}
}

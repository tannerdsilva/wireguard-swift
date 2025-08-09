import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64

internal struct HandshakeResponseMessage:Sendable {
	internal static func forgeResponseState(c cIn:Result32, h hIn:Result32, initiatorPeerIndex:PeerIndex, initiatorStaticPublicKey:UnsafePointer<PublicKey>, initiatorEphemeralPublicKey: PublicKey, preSharedKey:Result32) throws -> (c:Result32, h:Result32, payload:Payload) {
		var c = cIn
		var h = hIn
		return try c.RAW_access_staticbuff_mutating { cPtr in
			return try h.RAW_access_staticbuff_mutating { hPtr in
				// step 1: (Epriv, Epub) := DH-GENERATE()
				var ephiPrivate = try PrivateKey()
				return try PublicKey(privateKey:&ephiPrivate).RAW_access_staticbuff { ephiPublic in

					// step 2: c := KDF(c, Epub)
					cPtr.assumingMemoryBound(to:Result32.self).pointee = try wgKDFv2(Result32.self, key:cPtr, count:MemoryLayout<Result32>.size, data:ephiPublic, count:MemoryLayout<Result32>.size)
					
					// step 4: h := HASH(h || msg.ephemeral)
					var hasher = try WGHasherV2<Result32>()
					try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
					try hasher.update(ephiPublic, count:MemoryLayout<PublicKey>.size)
					hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

					// step 5: c := KDF(c, DH(Epriv, initiatorEpub))
					try withUnsafePointer(to:initiatorEphemeralPublicKey) { ephiKeyPublic in
						cPtr.assumingMemoryBound(to:Result32.self).pointee = try wgKDFv2(Result32.self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey: &ephiPrivate, publicKey: ephiKeyPublic))
					}
					
					// step 6: c := KDF(c, DH(Epriv, initiatorStaticPub))
					cPtr.assumingMemoryBound(to:Result32.self).pointee = try wgKDFv2(Result32.self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey: &ephiPrivate, publicKey: initiatorStaticPublicKey))

					// step 7: (c, T, k) := KDF^3(c, Q)
					var k:Result32
					let T:Result32
					(cPtr.assumingMemoryBound(to:Result32.self).pointee, T, k) = try wgKDFv2((Result32, Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:preSharedKey)
					
					// step 8: h := HASH(H || T)
					hasher = try WGHasherV2<Result32>()
					try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
					try hasher.update(T)
					hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

					// step 9: msg.empty := AEAD(k, 0, e, h)
					var e:[UInt8] = []
					let (_, emptyTag) = try aeadEncrypt(key:&k, counter:0, text:&e, aad:hPtr.assumingMemoryBound(to:Result32.self))
					
					// step 10: h := HASH(h || msg.empty)
					hasher = try WGHasherV2<Result32>()
					try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
					try hasher.update(emptyTag)
					hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

					return (cPtr.assumingMemoryBound(to:Result32.self).pointee, hPtr.assumingMemoryBound(to:Result32.self).pointee, Payload(responderIndex:try generateSecureRandomBytes(as:PeerIndex.self), initiatorIndex:initiatorPeerIndex, ephemeral:ephiPublic.assumingMemoryBound(to:PublicKey.self).pointee, emptyTag:emptyTag))
				}
			}
		}
	}
	
	internal static func finalizeResponseState(initiatorStaticPublicKey:UnsafePointer<PublicKey>, payload:consuming Payload) throws -> AuthenticatedPayload {
		// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
		var hasher = try WGHasherV2<Result32>()
		try hasher.update([UInt8]("mac1----".utf8))
		try hasher.update(initiatorStaticPublicKey)
		let mac1 = try wgMac(key:try hasher.finish(), data:copy payload)
		
		// step 15: msg.mac2 := 0^16
		return AuthenticatedPayload(payload:payload, msgMac1: mac1, msgMac2:Result16(RAW_staticbuff:Result16.RAW_staticbuff_zeroed()))
	}
	
	internal struct MAC1InvalidError:Swift.Error {}
	internal static func validateResponseMessage(c cIn:Result32, h hIn:Result32, message:UnsafePointer<HandshakeResponseMessage.AuthenticatedPayload>, initiatorStaticPrivateKey:UnsafePointer<PrivateKey>, initiatorEphemeralPrivateKey:UnsafePointer<PrivateKey>, preSharedKey:Result32) throws -> (c:Result32, h:Result32) {
		var c = cIn
		var h = hIn
		
		// setup: get responder public key
		let initiatorStaticPublicKey = PublicKey(privateKey:initiatorStaticPrivateKey)

		// step 0.5:
		var responderEphemeralPublicKey = message.pointee.payload.ephemeral

		// step 1: c := KDF(c, responderEpub)
		c = try! wgKDF(key:c, data:responderEphemeralPublicKey, type:1)[0]
		
		// step 4: h := HASH(h || msg.ephemeral)
		var hasher = try WGHasherV2<Result32>()
		try hasher.update(h)
		try hasher.update(responderEphemeralPublicKey)
		h = try hasher.finish()
		
		// step 5: c := KDF(c, DH(initiatorEpriv, responderEpub))
		c = try! wgKDF(key:c, data:try dhKeyExchange(privateKey: initiatorEphemeralPrivateKey, publicKey: &responderEphemeralPublicKey), type:1)[0]
		
		// step 6: c := KDF(c, DH(initiatorStaticPrivateKey, responderEpub))
		c = try! wgKDF(key:c, data:try dhKeyExchange(privateKey: initiatorStaticPrivateKey, publicKey: &responderEphemeralPublicKey), type:1)[0]
		
		// step 7: (c, T, k) := KDF^3(c, Q)
		var k:Result32
		var T:Result32
		var arr:[Result32]
		arr = try! wgKDF(key:c, data: preSharedKey, type:3)
		c = arr[0]; T = arr[1]; k = arr[2]
		
		// step 8: h := HASH(H || T)
		hasher = try WGHasherV2<Result32>()
		try hasher.update(h)
		try hasher.update(T)
		h = try hasher.finish()
		
		// step 9: msg.empty := AEAD(k, 0, e, h)
		var e:[UInt8] = []
		var msgEmpty = try! aeadDecrypt(key:&k, counter:0, cipherText:&e, aad:&h, tag:message.pointer(to:\.payload.emptyTag)!.pointee)

		// step 10: h := HASH(h || msg.empty)
		hasher = try WGHasherV2<Result32>()
		try hasher.update(h)
		try hasher.update(message.pointee.payload.emptyTag)
		h = try hasher.finish()
		
		// step 13: create MAC1
		hasher = try WGHasherV2<Result32>()
		try hasher.update([UInt8]("mac1----".utf8))
		try hasher.update(initiatorStaticPublicKey)
		let mac1 = try! wgMac(key:try hasher.finish(), data: message.pointee.payload)

		guard mac1 == message.pointee.msgMac1 else {
			throw MAC1InvalidError()
		}
		
		return (c, h)
	}
	
	@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PeerIndex.self, PublicKey.self, Tag.self)
	internal struct Payload:Sendable {
		/// message type (type and reserved)
		let typeHeader:TypeHeading
		/// responder's peer index (I_r)
		internal let responderIndex:PeerIndex
		/// sender's peer index
		internal let initiatorIndex:PeerIndex
		/// ephemeral key
		internal let ephemeral:PublicKey
		/// empty tag of message
		internal let emptyTag:Tag

		/// initializes a new HandshakeResponseMessage
		fileprivate init(responderIndex:PeerIndex, initiatorIndex:PeerIndex, ephemeral:PublicKey, emptyTag:Tag) {
			self.typeHeader = 0x2
			self.initiatorIndex = initiatorIndex
			self.responderIndex = responderIndex
			self.ephemeral = ephemeral
			self.emptyTag = emptyTag
		}
	}
	
	@RAW_staticbuff(concat:Payload.self, Result16.self, Result16.self)
	internal struct AuthenticatedPayload:Sendable, Sequence {
		let payload:Payload
		let msgMac1:Result16
		let msgMac2:Result16
		fileprivate init(payload:Payload, msgMac1:Result16, msgMac2:Result16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}
	}
}

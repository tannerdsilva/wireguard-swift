import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64

extension Message {
	public struct Response {
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PeerIndex.self, PublicKey.self, Tag.self)
		public struct Payload:Sendable {
			/// message type (type and reserved)
			public let typeHeader:TypeHeading
			/// responder's peer index (I_r)
			public let responderIndex:PeerIndex
			/// sender's peer index
			public let initiatorIndex:PeerIndex
			/// ephemeral key
			public let ephemeral:PublicKey
			/// empty tag of message
			public let emptyTag:Tag

			/// initializes a new HandshakeResponseMessage
			fileprivate init(responderIndex:PeerIndex, initiatorIndex:PeerIndex, ephemeral:PublicKey, emptyTag:Tag) {
				self.typeHeader = 0x2
				self.initiatorIndex = initiatorIndex
				self.responderIndex = responderIndex
				self.ephemeral = ephemeral
				self.emptyTag = emptyTag
			}

			public borrowing func finalize(initiatorStaticPublicKey:UnsafePointer<PublicKey>) throws -> Authenticated {
				try withUnsafePointer(to:self) { selfPtr in
					// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
					var hasher = try WGHasherV2<Result32>()
					try hasher.update([UInt8]("mac1----".utf8))
					try hasher.update(initiatorStaticPublicKey)
					let mac1 = try wgMac(key:try hasher.finish(), data:selfPtr.pointee)
					
					// step 15: msg.mac2 := 0^16
					return Authenticated(payload:selfPtr.pointee, msgMac1: mac1, msgMac2:Result16(RAW_staticbuff:Result16.RAW_staticbuff_zeroed()))
				}
			}

			public static func forge(c cIn:consuming Result32, h hIn:consuming Result32, initiatorPeerIndex:PeerIndex, initiatorStaticPublicKey:UnsafePointer<PublicKey>, initiatorEphemeralPublicKey: PublicKey, preSharedKey:Result32) throws -> (c:Result32, h:Result32, payload:Payload) {
				return try cIn.RAW_access_staticbuff_mutating { cPtr in
					return try hIn.RAW_access_staticbuff_mutating { hPtr in
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
		}
	}
}

extension Message.Response.Payload {
	@RAW_staticbuff(concat:Message.Response.Payload.self, Result16.self, Result16.self)
	public struct Authenticated:Sendable, Sequence {
		public enum Error:Swift.Error {
			case mac1Invalid
			case mac2Invalid
		}
		public let payload:Message.Response.Payload
		public let msgMac1:Result16
		public let msgMac2:Result16
		fileprivate init(payload:Message.Response.Payload, msgMac1:Result16, msgMac2:Result16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}

		public borrowing func validate(c cIn:consuming Result32, h hIn:consuming Result32, initiatorStaticPrivateKey:UnsafePointer<PrivateKey>, initiatorEphemeralPrivateKey:UnsafePointer<PrivateKey>, preSharedKey:Result32) throws -> (c:Result32, h:Result32) {
			return try withUnsafePointer(to:self) { selfPtr in
				try cIn.RAW_access_staticbuff_mutating { cPtr in
					try hIn.RAW_access_staticbuff_mutating { hPtr in
						// setup: get responder public key
						let initiatorStaticPublicKey = PublicKey(privateKey:initiatorStaticPrivateKey)

						// step 0.5:
						var responderEphemeralPublicKey = selfPtr.pointer(to:\.payload.ephemeral)!.pointee

						// step 1: c := KDF(c, responderEpub)
						cPtr.assumingMemoryBound(to:Result32.self).pointee = try! wgKDFv2((Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:responderEphemeralPublicKey)
						
						// step 4: h := HASH(h || msg.ephemeral)
						var hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(responderEphemeralPublicKey)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()
						
						// step 5: c := KDF(c, DH(initiatorEpriv, responderEpub))
						cPtr.assumingMemoryBound(to:Result32.self).pointee = try! wgKDFv2((Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey: initiatorEphemeralPrivateKey, publicKey: &responderEphemeralPublicKey))
						
						// step 6: c := KDF(c, DH(initiatorStaticPrivateKey, responderEpub))
						cPtr.assumingMemoryBound(to:Result32.self).pointee = try! wgKDFv2((Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey: initiatorStaticPrivateKey, publicKey: &responderEphemeralPublicKey))
						
						// step 7: (c, T, k) := KDF^3(c, Q)
						var k:Result32
						var T:Result32
						(cPtr.assumingMemoryBound(to:Result32.self).pointee, T, k) = try! wgKDFv2((Result32, Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data: preSharedKey)
						
						// step 8: h := HASH(H || T)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(T)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()
						
						// step 9: msg.empty := AEAD(k, 0, e, h)
						var e:[UInt8] = []
						var msgEmpty = try! aeadDecrypt(key:&k, counter:0, cipherText:&e, aad:hPtr.assumingMemoryBound(to:Result32.self), tag:selfPtr.pointer(to:\.payload.emptyTag)!.pointee)

						// step 10: h := HASH(h || msg.empty)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.emptyTag)!.pointee)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()
						
						// step 13: create MAC1
						hasher = try WGHasherV2<Result32>()
						try hasher.update([UInt8]("mac1----".utf8))
						try hasher.update(initiatorStaticPublicKey)
						let mac1 = try! wgMac(key:try hasher.finish(), data: selfPtr.pointer(to: \.payload)!.pointee)
						guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
							throw Error.mac1Invalid
						}

						return (cPtr.assumingMemoryBound(to:Result32.self).pointee, hPtr.assumingMemoryBound(to:Result32.self).pointee)
					}
				}
			}
		}
	}
}
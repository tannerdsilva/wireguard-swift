import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_xchachapoly
import RAW_base64
import NIO



extension Message {
	public struct Initiation {
		/// this message is described in the wireguard whitepaper in section 5.4.2
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PublicKey.self, PublicKey.self, RAW_chachapoly.Tag.self, TAI64N.self, RAW_chachapoly.Tag.self)
		public struct Payload:Sendable {
			/// message type
			public let typeHeader:TypeHeading
			/// initiator's peer index
			public let initiatorPeerIndex:PeerIndex
			/// ephemeral key content
			public let ephemeral:PublicKey
			/// static region of the message
			public let staticRegion:PublicKey
			public let staticTag:RAW_chachapoly.Tag
			/// timestamp associated with the message
			public let timestamp:TAI64N
			public let timestampTag:RAW_chachapoly.Tag

			/// initializes a new HandshakeInitiationMessage
			fileprivate init(initiatorPeerIndex:PeerIndex, ephemeral:PublicKey, staticRegion:PublicKey, staticTag:RAW_chachapoly.Tag, timestamp:TAI64N, timestampTag:RAW_chachapoly.Tag) {
				self.typeHeader = 0x1
				self.initiatorPeerIndex = initiatorPeerIndex
				self.ephemeral = ephemeral
				self.staticRegion = staticRegion
				self.staticTag = staticTag
				self.timestamp = timestamp
				self.timestampTag = timestampTag
			}

			public static func forge(initiatorStaticPrivateKey:UnsafePointer<PrivateKey>, responderStaticPublicKey:UnsafePointer<PublicKey>, index:PeerIndex? = nil) throws -> (c:Result32, h:Result32, ephiPrivateKey:PrivateKey, payload:Payload) {
				// setup: get initiator public key
				var initiatorStaticPublicKey = PublicKey(privateKey:initiatorStaticPrivateKey)

				// step 1: calculate the hash of the static construction string
				var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
				return try c.RAW_access_staticbuff_mutating { cPtr in

					// step 2: h = hash(ci || identifier)
					var hasher = try WGHasherV2<Result32>()
					try hasher.update(cPtr, count:MemoryLayout<Result32>.size)
					try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
					var h = try hasher.finish()
					return try h.RAW_access_staticbuff_mutating { hPtr in
						
						// step 3: h = hash(h || responderStaticPublicKey public key)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(responderStaticPublicKey, count:MemoryLayout<PublicKey>.size)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

						// step 4: generate ephemeral keys
						var ephiPrivate = try PrivateKey()
						return try PublicKey(privateKey:&ephiPrivate).RAW_access_staticbuff { ephiPublicPtr in

							// step 5: c = KDF^1(c, e.Public)
							cPtr.assumingMemoryBound(to:Result32.self).pointee = try wgKDFv2(Result32.self, key:cPtr, count:MemoryLayout<Result32>.size, data:ephiPublicPtr, count:MemoryLayout<PublicKey>.size)
							
							// step 6: assign e.Public to the ephemeral field

							// step 7: h = hash(h | ephiPublic)
							hasher = try WGHasherV2<Result32>()
							try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
							try hasher.update(ephiPublicPtr, count:MemoryLayout<PublicKey>.size)
							hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

							// step 8: (c, k) = KDF^2(c, dh(eiPriv, srPublic))
							var k:Result32
							(cPtr.assumingMemoryBound(to:Result32.self).pointee, k) = try wgKDFv2((Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey:&ephiPrivate, publicKey:responderStaticPublicKey))

							// step 9: msg.static = AEAD(k, 0, siPublic, h)
							let (msgStatic, msgTag) = try aeadEncrypt(key:&k, counter:0, text:&initiatorStaticPublicKey, aad:hPtr.assumingMemoryBound(to:Result32.self))

							// step 10: h = hash(h || msg.static)
							hasher = try WGHasherV2<Result32>()
							try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
							try hasher.update(msgStatic)
							try hasher.update(msgTag)
							try hasher.finish(into:hPtr)

							// step 11: c, k) = kdf^2(c, dh(sipriv, srpub))
							(cPtr.assumingMemoryBound(to:Result32.self).pointee, k) = try wgKDFv2((Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey:initiatorStaticPrivateKey, publicKey:responderStaticPublicKey))

							// step 12: msg.timestamp = AEAD(k, 0, timestamp(), h)
							return try withUnsafePointer(to:TAI64N()) { taiPointer in
								let (tsDat, tsTag) = try aeadEncrypt(key:&k, counter:0, text:taiPointer, aad:hPtr.assumingMemoryBound(to:Result32.self))

								// step 13: h = hash(h || msg.timestamp)
								hasher = try WGHasherV2<Result32>()
								try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
								try hasher.update(tsDat)
								try hasher.update(tsTag)
								hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

								// additional step: create new peer index if necessary
								var myIndex:PeerIndex
								if(index == nil) {
									myIndex = try generateSecureRandomBytes(as:PeerIndex.self)
								} else {
									myIndex = index!
								}
								return (cPtr.assumingMemoryBound(to:Result32.self).pointee, hPtr.assumingMemoryBound(to:Result32.self).pointee, ephiPrivate, Payload(initiatorPeerIndex:myIndex, ephemeral:ephiPublicPtr.assumingMemoryBound(to:PublicKey.self).pointee, staticRegion:msgStatic, staticTag:msgTag, timestamp:tsDat, timestampTag:tsTag))
							}
						}
					}
				}
			}

			public borrowing func finalize(responderStaticPublicKey:UnsafePointer<PublicKey>, cookie:CookieReplyMessage.Payload? = nil) throws -> Authenticated {
				try withUnsafePointer(to:self) { selfPtr in
					// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
					var hasher = try WGHasherV2<Result32>()
					try hasher.update([UInt8]("mac1----".utf8))
					try hasher.update(responderStaticPublicKey)
					let mac1 = try wgMac(key:try hasher.finish(), data:selfPtr.pointee)
					
					// step 15: msg.mac2 := 0^16
					var mac2:Result16
					// if cookie: msg.mac2 := MAC(cookie.msg, msgb)
					if cookie != nil {
						var hasher = try WGHasherV2<RAW_xchachapoly.Key>()
						try hasher.update([UInt8]("cookie--".utf8))
						try hasher.update(responderStaticPublicKey)
						let key = try hasher.finish()
						let cookieMsg = try xaeadDecrypt(key:key, nonce: cookie!.nonce, cipherText: cookie!.cookieMsg, aad: mac1, tag: cookie!.cookieTag)
						mac2 = try wgMac(key:cookieMsg, data:MSGb(payload:selfPtr.pointee, msgMac1: mac1))
					} else {
						mac2 = Result16(RAW_staticbuff:Result16.RAW_staticbuff_zeroed())
					}

					return Authenticated(payload:selfPtr.pointee, msgMac1: mac1, msgMac2: mac2)
				}
			}
		}
	}
}

extension Message.Initiation.Payload {
	@RAW_staticbuff(concat:Message.Initiation.Payload.self, Result16.self, Result16.self)
	public struct Authenticated:Sendable, Sequence {
		public enum Error:Swift.Error {
			case mac1Invalid
			case mac2Invalid
		}
		public let payload:Message.Initiation.Payload
		public let msgMac1:Result16
		public let msgMac2:Result16
		fileprivate init(payload:Message.Initiation.Payload, msgMac1:Result16, msgMac2:Result16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}

		public borrowing func validateUnderLoad(responderStaticPrivateKey:UnsafePointer<PrivateKey>, R:Result8, A:SocketAddress) throws {
			try withUnsafePointer(to:self) { selfPtr in
				// setup: get responder public key
				let responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
				
				// Try validating msgMac1
				var hasher = try WGHasherV2<Result32>()
				try hasher.update([UInt8]("mac1----".utf8))
				try hasher.update(responderStaticPublicKey)
				let mac1 = try wgMACv2(key:try hasher.finish(), data:selfPtr.pointer(to:\.payload)!.pointee)
				guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
					throw Error.mac1Invalid
				}
				
				// Try validating msgMac2
				var address:[UInt8]
				switch A {
					case .v4(let addr):
						let ipBytes = withUnsafeBytes(of: addr.address.sin_addr.s_addr.bigEndian) { Array($0) }
						let portBytes = withUnsafeBytes(of: UInt16(A.port!).bigEndian) { Array($0) }
						address = ipBytes + portBytes
						
					case .v6(let addr):
						let ipBytes = withUnsafeBytes(of: addr.address.sin6_addr.__u6_addr.__u6_addr8) { Array($0) }
						let portBytes = withUnsafeBytes(of: UInt16(A.port!).bigEndian) { Array($0) }
						address = ipBytes + portBytes
						
					default:
						address = []
				}
				
				let T = try wgMACv2(key:R, data:address)
				let mac2 = try wgMACv2(key:T, data:MSGb(payload:selfPtr.pointer(to:\.payload)!.pointee, msgMac1:mac1))
				guard mac2 == selfPtr.pointer(to:\.msgMac2)!.pointee else {
					throw Error.mac2Invalid
				}
			}
		}

		public borrowing func validate(responderStaticPrivateKey:UnsafePointer<PrivateKey>) throws -> (c:Result32, h:Result32, initPublicKey:PublicKey, timestamp:TAI64N) {
			return try withUnsafePointer(to:self) { selfPtr in
				// setup: get responder public key
				let responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
				
				// step 1: calculate the hash of the static construction string
				var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
				return try c.RAW_access_staticbuff_mutating { cPtr in
					// step 2: h = hash(ci || identifier)
					var hasher = try WGHasherV2<Result32>()
					try hasher.update(cPtr, count:MemoryLayout<Result32>.size)
					try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
					var h = try hasher.finish()
					return try h.RAW_access_staticbuff_mutating { hPtr in
						// step 3: h = hash(h || responderStaticPublicKey)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(responderStaticPublicKey)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

						// step 3.5 - store the initiators ephemeral key
						var initiatorEphemeralPublicKey = selfPtr.pointer(to:\.payload.ephemeral)!.pointee
					
						// step 5: c = KDF^1(c, initiatorEphemeralPublicKey)
						cPtr.assumingMemoryBound(to:Result32.self).pointee = try wgKDFv2(Result32.self, key:cPtr, count:MemoryLayout<Result32>.size, data:initiatorEphemeralPublicKey)

						// step 6: h = hash(h || initiatorEphemeralPublicKey)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(initiatorEphemeralPublicKey)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

						// step 7: (c, k) = KDF^2(c, dh(responderStaticPrivateKey, initiatorEphemeralPublicKey))
						var k:Result32
						(cPtr.assumingMemoryBound(to:Result32.self).pointee, k) = try wgKDFv2((Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initiatorEphemeralPublicKey))

						// step 8: decrypt the msg.static to determine the initStaticPublicKey
						var initStaticPublicKey = try aeadDecryptV2(as:PublicKey.self, key:k, counter:0, cipherText:selfPtr.pointer(to:\.payload.staticRegion)!.pointee, aad:hPtr.assumingMemoryBound(to:Result32.self).pointee, tag:selfPtr.pointer(to:\.payload.staticTag)!.pointee)

						let publickey = String(try RAW_base64.encode(initStaticPublicKey))
					
						// step 9: h = hash(h || msg.static)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.staticRegion)!)
						try hasher.update(selfPtr.pointer(to:\.payload.staticTag)!)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

						// step 10: (c, k) = KDF^2(c, dh(msg.static [initiatorStaticPublicKey], responderStaticPrivateKey))
						(cPtr.assumingMemoryBound(to:Result32.self).pointee, k) = try wgKDFv2((Result32, Result32).self, key:cPtr, count:MemoryLayout<Result32>.size, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initStaticPublicKey))

						// step 11: descrypt the msg.timestamp to find the intial timestamp
						let sentTimestamp = try aeadDecryptV2(as:TAI64N.self, key:k, counter:0, cipherText:selfPtr.pointer(to:\.payload.timestamp)!.pointee, aad:hPtr.assumingMemoryBound(to:Result32.self).pointee, tag:selfPtr.pointer(to:\.payload.timestampTag)!.pointee)

						// step 12: h = hash(h || msg.static)
						hasher = try WGHasherV2<Result32>()
						try hasher.update(hPtr, count:MemoryLayout<Result32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.timestamp)!)
						try hasher.update(selfPtr.pointer(to:\.payload.timestampTag)!)
						hPtr.assumingMemoryBound(to:Result32.self).pointee = try hasher.finish()

						// step 13: create MAC1
						hasher = try WGHasherV2<Result32>()
						try hasher.update([UInt8]("mac1----".utf8))
						try hasher.update(responderStaticPublicKey)
						let mac1 = try wgMACv2(key:try hasher.finish(), data:selfPtr.pointer(to:\.payload)!.pointee)
						guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
							throw Error.mac1Invalid
						}

						return (cPtr.assumingMemoryBound(to:Result32.self).pointee, hPtr.assumingMemoryBound(to:Result32.self).pointee, initStaticPublicKey, sentTimestamp)
					}
				}
			}
		}
	}
}
extension Message.Initiation.Payload {
	@RAW_staticbuff(concat:Message.Initiation.Payload.self, Result16.self)
	fileprivate struct MSGb:Sendable {
		fileprivate let payload:Message.Initiation.Payload
		fileprivate let msgMac1:Result16
		fileprivate init(payload:Message.Initiation.Payload, msgMac1:Result16) {
			self.payload = payload
			self.msgMac1 = msgMac1
		}
	}
}
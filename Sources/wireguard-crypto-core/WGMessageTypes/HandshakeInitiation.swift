import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_xchachapoly
import RAW_base64
import bedrock_ip // replacement target for NIO.SocketAddress

extension Message {
	/// A handshake initiation message.
	public struct Initiation {
		/// The serialized contents of a handshake initiation message, described in
		/// section 5.4.2 of the WireGuard whitepaper.
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PublicKey.self, PublicKey.self, RAW_chachapoly.Tag.self, TAI64N.self, RAW_chachapoly.Tag.self)
		public struct Payload:Sendable {
			/// The message type header (type and reserved bytes).
			public let typeHeader:TypeHeading
			/// The initiator's peer index.
			public let initiatorPeerIndex:PeerIndex
			/// The ephemeral key.
			public let ephemeral:PublicKey
			/// The encrypted static region of the message.
			public let staticRegion:PublicKey
			/// The authentication tag for the static region.
			public let staticTag:RAW_chachapoly.Tag
			/// The timestamp associated with the message.
			public let timestamp:TAI64N
			/// The authentication tag for the timestamp.
			public let timestampTag:RAW_chachapoly.Tag

			/// Creates a new handshake initiation payload.
			fileprivate init(initiatorPeerIndex:PeerIndex, ephemeral:PublicKey, staticRegion:PublicKey, staticTag:RAW_chachapoly.Tag, timestamp:TAI64N, timestampTag:RAW_chachapoly.Tag) {
				self.typeHeader = 0x1
				self.initiatorPeerIndex = initiatorPeerIndex
				self.ephemeral = ephemeral
				self.staticRegion = staticRegion
				self.staticTag = staticTag
				self.timestamp = timestamp
				self.timestampTag = timestampTag
			}

			/// Builds a handshake initiation payload for the given keys.
			/// - Parameters:
			///   - initiatorStaticPrivateKey: The initiator's static private key.
			///   - responderStaticPublicKey: The responder's static public key.
			///   - index: The initiator peer index to advertise; a random one is generated
			///     when `nil` (the default).
			/// - Returns: The working chaining key, the working hash, the ephemeral
			///   private key, and the forged payload.
			/// - Throws: If any cryptographic operation fails.
			public static func forge(initiatorStaticPrivateKey:MemoryGuarded<PrivateKey>, responderStaticPublicKey:UnsafePointer<PublicKey>, initiatorPeerIndex index:PeerIndex? = nil) throws -> (c:Result.Bytes32, h:Result.Bytes32, ephiPrivateKey:MemoryGuarded<PrivateKey>, payload:Payload) {
				// setup: get initiator public key
				var initiatorStaticPublicKey = PublicKey(privateKey:initiatorStaticPrivateKey)

				// step 1: calculate the hash of the static construction string
				var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
				return try c.RAW_access_mutable(UnsafeMutableRawBufferPointer.self) { cPtr in

					// step 2: h = hash(ci || identifier)
					var hasher = try WGHasher<Result.Bytes32>()
					try hasher.update(cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
					try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
					var h = try hasher.finishDecoded()
					return try h.RAW_access_mutable(UnsafeMutableRawBufferPointer.self) { hPtr in
						
						// step 3: h = hash(h || responderStaticPublicKey public key)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(responderStaticPublicKey, count:MemoryLayout<PublicKey>.size)
						hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

						// step 4: generate ephemeral keys
						let ephiPrivate = try MemoryGuarded<PrivateKey>.new()
						return try PublicKey(privateKey:ephiPrivate).RAW_access_immutable(UnsafeRawBufferPointer.self) { ephiPublicPtr in

							// step 5: c = KDF^1(c, e.Public)
							cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2(Result.Bytes32.self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:ephiPublicPtr.baseAddress!, count:MemoryLayout<PublicKey>.size)
							
							// step 6: assign e.Public to the ephemeral field

							// step 7: h = hash(h | ephiPublic)
							hasher = try WGHasher<Result.Bytes32>()
							try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
							try hasher.update(ephiPublicPtr.baseAddress!, count:MemoryLayout<PublicKey>.size)
							hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

							// step 8: (c, k) = KDF^2(c, dh(eiPriv, srPublic))
							var k:Result.Bytes32
							(cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:ephiPrivate, publicKey:responderStaticPublicKey.pointee))

							// step 9: msg.static = AEAD(k, 0, siPublic, h)
							let (msgStatic, msgTag) = try aeadEncrypt(key:&k, counter:0, text:&initiatorStaticPublicKey, aad:hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self))

							// step 10: h = hash(h || msg.static)
							hasher = try WGHasher<Result.Bytes32>()
							try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
							try hasher.update(msgStatic)
							try hasher.update(msgTag)
							try hasher.finish(into:hPtr.baseAddress!)

							// step 11: c, k) = kdf^2(c, dh(sipriv, srpub))
							(cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:initiatorStaticPrivateKey, publicKey:responderStaticPublicKey.pointee))

							// step 12: msg.timestamp = AEAD(k, 0, timestamp(), h)
							return try withUnsafePointer(to:TAI64N()) { taiPointer in
								let (tsDat, tsTag) = try aeadEncrypt(key:&k, counter:0, text:taiPointer, aad:hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self))

								// step 13: h = hash(h || msg.timestamp)
								hasher = try WGHasher<Result.Bytes32>()
								try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
								try hasher.update(tsDat)
								try hasher.update(tsTag)
								hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

								// additional step: create new peer index if necessary
								var myIndex:PeerIndex
								if(index == nil) {
									myIndex = try PeerIndex.random()
								} else {
									myIndex = index!
								}
								return (cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, ephiPrivate, Payload(initiatorPeerIndex:myIndex, ephemeral:ephiPublicPtr.baseAddress!.assumingMemoryBound(to:PublicKey.self).pointee, staticRegion:msgStatic, staticTag:msgTag, timestamp:tsDat, timestampTag:tsTag))
							}
						}
					}
				}
			}

			/// Computes `msg.mac1` and `msg.mac2` for this payload, yielding an
			/// `Authenticated` initiation message.
			/// - Parameters:
			///   - responderStaticPublicKey: The responder's static public key.
			///   - cookie: The cookie reply to incorporate into `msg.mac2`, if the
			///     responder is under load.
			///   - savedMac1: The mac1 value saved with the cookie, used as AEAD
			///     associated data when decrypting the cookie. Must be provided when
			///     `cookie` is.
			/// - Returns: The authenticated initiation message.
			/// - Throws: If any cryptographic operation fails.
			public borrowing func finalize(responderStaticPublicKey:UnsafePointer<PublicKey>, cookie:Message.Cookie.Payload? = nil, savedMac1:Result.Bytes16? = nil) throws -> Authenticated {
				try withUnsafePointer(to:self) { selfPtr in
					// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
					var hasher = try WGHasher<Result.Bytes32>()
					try hasher.update([UInt8]("mac1----".utf8))
					try hasher.update(responderStaticPublicKey)
					let mac1 = try wgMAC(key:try hasher.finishDecoded(), data:selfPtr.pointee)
					
					// step 15: msg.mac2 := 0^16
					let mac2:Result.Bytes16
					// if cookie: msg.mac2 := MAC(cookie.msg, msgb)
					if cookie != nil {
						var hasher = try WGHasher<RAW_xchachapoly.Key>()
						try hasher.update([UInt8]("cookie--".utf8))
						try hasher.update(responderStaticPublicKey)
						let key = try hasher.finishDecoded()
						let cookieMsg = try xaeadDecrypt(key:key, nonce: cookie!.nonce, cipherText: cookie!.cookieMsg, aad: savedMac1!, tag: cookie!.cookieTag)
						mac2 = try wgMAC(key:cookieMsg, data:MSGb(payload:selfPtr.pointee, msgMac1: mac1))
					} else {
						mac2 = Result.Bytes16.RAW_comparable_fixed_theoretical_min()
					}

					return Authenticated(payload:selfPtr.pointee, msgMac1: mac1, msgMac2: mac2)
				}
			}
		}
	}
}

extension Message.Initiation.Payload {
	/// A handshake initiation message with MAC1 and MAC2 appended.
	@RAW_staticbuff(concat:Message.Initiation.Payload.self, Result.Bytes16.self, Result.Bytes16.self)
	public struct Authenticated:Sendable {
		/// Errors that can occur while validating an initiation message.
		public enum Error:Swift.Error {
			/// The message's MAC1 did not match.
			case mac1Invalid
			/// The message's MAC2 did not match.
			case mac2Invalid
		}
		/// The underlying initiation payload.
		public let payload:Message.Initiation.Payload
		/// The message's MAC1.
		public let msgMac1:Result.Bytes16
		/// The message's MAC2.
		public let msgMac2:Result.Bytes16
		/// Creates an authenticated initiation message.
		public init(payload:Message.Initiation.Payload, msgMac1:Result.Bytes16, msgMac2:Result.Bytes16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}

		/// Validates both MACs of the message against the responder's static private
		/// key and cookie state.
		/// - Parameters:
		///   - responderStaticPrivateKey: The responder's static private key.
		///   - R: The responder's current per-peer cookie secret.
		///   - oldR: A previous per-peer cookie secret to also accept, or `nil`.
		///   - endpoint: The source endpoint of the message.
		/// - Throws: `Error.mac1Invalid` or `Error.mac2Invalid` if validation fails.
		public func validateUnderLoad(responderStaticPrivateKey:MemoryGuarded<PrivateKey>, R:Result.Bytes8, oldR:Result.Bytes8?, endpoint:Endpoint) throws {
			try withUnsafePointer(to:self) { selfPtr in
				// setup: get responder public key
				let responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
				
				// Try validating msgMac1
				var hasher = try WGHasher<Result.Bytes32>()
				try hasher.update([UInt8]("mac1----".utf8))
				try hasher.update(responderStaticPublicKey)
				let mac1 = try wgMAC(key:try hasher.finishDecoded(), data:selfPtr.pointer(to:\.payload)!.pointee)
				guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
					throw Error.mac1Invalid
				}
				
				guard try isMac2Valid(R:R, oldR:oldR, endpoint:endpoint) else {
					throw Error.mac2Invalid
				}
			}
		}

		/// Cheaply validates `msg.mac1` against a pre-computed MAC1 key. Unlike
		/// `validate(_:)`, this performs no Curve25519 work and depends only on the
		/// responder's public key and the raw packet, so it can be used as a cheap
		/// pre-DH authenticity gate to reject unauthenticated initiations before
		/// expending CPU (DoS hardening; whitepaper sections 5.3 and 5.4.4).
		/// - Parameter precomputedKey: `HASH(LABEL-MAC1 || Spub(m'))`.
		/// - Throws: `Error.mac1Invalid` if the MAC does not match.
		public borrowing func validateMac1(precomputedKey:Result.Bytes32) throws {
			try withUnsafePointer(to:self) { selfPtr in
				let mac1 = try wgMAC(key:precomputedKey, data:selfPtr.pointer(to:\.payload)!.pointee)
				guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
					throw Error.mac1Invalid
				}
			}
		}

		/// Computes the expected value of `msg.mac2` for this message given the
		/// responder's per-peer-cookie secret `R` and the source `endpoint` from
		/// which the message arrived. Per the whitepaper (sections 5.4.4 and 5.4.7):
		/// `T := Mac(R, endpoint)` and `msg.mac2 := Mac(T, msgβ)`, where `msgβ` is
		/// all bytes prior to `mac2`.
		/// - Parameters:
		///   - R: The responder's per-peer cookie secret.
		///   - endpoint: The source endpoint of the message.
		/// - Returns: The expected `msg.mac2` value.
		/// - Throws: If key derivation fails.
		public borrowing func computeExpectedMac2(R:Result.Bytes8, endpoint:Endpoint) throws -> Result.Bytes16 {
			try withUnsafePointer(to:self) { selfPtr in
				let T:Result.Bytes16
				switch endpoint {
					case .v4(let v4ep):
						T = try wgMAC(key:R, data:v4ep)
					case .v6(let v6ep):
						T = try wgMAC(key:R, data:v6ep)
				}
				return try wgMAC(key:T, data:MSGb(payload:selfPtr.pointer(to:\.payload)!.pointee, msgMac1:selfPtr.pointer(to:\.msgMac1)!.pointee))
			}
		}

		/// Returns `true` if the message carries a valid `msg.mac2` for the given
		/// cookie secret(s) and source endpoint. The all-zero `mac2` (`0¹⁶`) is always
		/// accepted here, since a peer without a cookie legitimately sends `mac2 := 0¹⁶`;
		/// whether that zero value is *acceptable* is a policy decision made by the
		/// caller based on whether the responder is under load (the whitepaper only
		/// *requires* a valid non-zero mac2 when the responder is under load).
		/// - Parameters:
		///   - R: The responder's current per-peer cookie secret.
		///   - oldR: A previous per-peer cookie secret to also accept, or `nil`.
		///   - endpoint: The source endpoint of the message.
		/// - Returns: `true` if the message carries a valid `mac2`.
		/// - Throws: If key derivation fails.
		public borrowing func isMac2Valid(R:Result.Bytes8, oldR:Result.Bytes8?, endpoint:Endpoint) throws -> Bool {
			let zeroMac2 = Result.Bytes16.RAW_comparable_fixed_theoretical_min()
			if msgMac2 == zeroMac2 {
				return true
			}
			if try computeExpectedMac2(R:R, endpoint:endpoint) == msgMac2 {
				return true
			}
			if let oldR = oldR, try computeExpectedMac2(R:oldR, endpoint:endpoint) == msgMac2 {
				return true
			}
			return false
		}
		
		/// Validates the message using the responder's static private key and the
		/// stored handshake chain state.
		/// - Parameter responderStaticPrivateKey: The responder's static private key.
		/// - Returns: The working chaining key, the working hash, the initiator's
		///   static public key, and the decoded initiation timestamp.
		/// - Throws: `Error.mac1Invalid` if the MAC does not match, or any
		///   cryptographic operation fails.
		public borrowing func validate(responderStaticPrivateKey:MemoryGuarded<PrivateKey>) throws -> (c:Result.Bytes32, h:Result.Bytes32, initPublicKey:PublicKey, timestamp:TAI64N) {
			return try withUnsafePointer(to:self) { selfPtr in
				// setup: get responder public key
				let responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
				
				// step 1: calculate the hash of the static construction string
				var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
				return try c.RAW_access_mutable(UnsafeMutableRawBufferPointer.self) { cPtr in
					// step 2: h = hash(ci || identifier)
					var hasher = try WGHasher<Result.Bytes32>()
					try hasher.update(cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
					try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
					var h = try hasher.finishDecoded()
					return try h.RAW_access_mutable(UnsafeMutableRawBufferPointer.self) { hPtr in
						// step 3: h = hash(h || responderStaticPublicKey)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(responderStaticPublicKey)
						hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

						// step 3.5 - store the initiators ephemeral key
						let initiatorEphemeralPublicKey = selfPtr.pointer(to:\.payload.ephemeral)!.pointee
					
						// step 5: c = KDF^1(c, initiatorEphemeralPublicKey)
						cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2(Result.Bytes32.self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:initiatorEphemeralPublicKey)

						// step 6: h = hash(h || initiatorEphemeralPublicKey)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(initiatorEphemeralPublicKey)
						hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

						// step 7: (c, k) = KDF^2(c, dh(responderStaticPrivateKey, initiatorEphemeralPublicKey))
						var k:Result.Bytes32
						(cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:initiatorEphemeralPublicKey))

						// step 8: decrypt the msg.static to determine the initStaticPublicKey
						let initStaticPublicKey = try aeadDecryptV2(as:PublicKey.self, key:k, counter:0, cipherText:selfPtr.pointer(to:\.payload.staticRegion)!.pointee, aad:hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, tag:selfPtr.pointer(to:\.payload.staticTag)!.pointee)
					
						// step 9: h = hash(h || msg.static)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.staticRegion)!)
						try hasher.update(selfPtr.pointer(to:\.payload.staticTag)!)
						hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

						// step 10: (c, k) = KDF^2(c, dh(msg.static [initiatorStaticPublicKey], responderStaticPrivateKey))
						(cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:initStaticPublicKey))

						// step 11: descrypt the msg.timestamp to find the intial timestamp
						let sentTimestamp = try aeadDecryptV2(as:TAI64N.self, key:k, counter:0, cipherText:selfPtr.pointer(to:\.payload.timestamp)!.pointee, aad:hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, tag:selfPtr.pointer(to:\.payload.timestampTag)!.pointee)

						// step 12: h = hash(h || msg.static)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr.baseAddress!, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.timestamp)!)
						try hasher.update(selfPtr.pointer(to:\.payload.timestampTag)!)
						hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finishDecoded()

						// step 13: create MAC1
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update([UInt8]("mac1----".utf8))
						try hasher.update(responderStaticPublicKey)
						let mac1 = try wgMAC(key:try hasher.finishDecoded(), data:selfPtr.pointer(to:\.payload)!.pointee)
						guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
							throw Error.mac1Invalid
						}

						return (cPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, hPtr.baseAddress!.assumingMemoryBound(to:Result.Bytes32.self).pointee, initStaticPublicKey, sentTimestamp)
					}
				}
			}
		}
	}
}
extension Message.Initiation.Payload {
	@RAW_staticbuff(concat:Message.Initiation.Payload.self, Result.Bytes16.self)
	fileprivate struct MSGb:Sendable {
		fileprivate let payload:Message.Initiation.Payload
		fileprivate let msgMac1:Result.Bytes16
		fileprivate init(payload:Message.Initiation.Payload, msgMac1:Result.Bytes16) {
			self.payload = payload
			self.msgMac1 = msgMac1
		}
	}
}

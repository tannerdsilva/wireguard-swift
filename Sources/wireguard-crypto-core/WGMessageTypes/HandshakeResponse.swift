import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64

extension Message {
	/// A handshake response message.
	public struct Response {
		/// The serialized contents of a handshake response message.
		@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PeerIndex.self, PublicKey.self, Tag.self)
		public struct Payload:Sendable {
			/// The message type header (type and reserved bytes).
			public let typeHeader:TypeHeading
			/// The responder's peer index (I_r).
			public let responderIndex:PeerIndex
			/// The initiator's peer index.
			public let initiatorIndex:PeerIndex
			/// The responder's ephemeral key.
			public let ephemeral:PublicKey
			/// The tag authenticating the empty AEAD plaintext.
			public let emptyTag:Tag

			/// Creates a new handshake response payload.
			fileprivate init(responderIndex:PeerIndex, initiatorIndex:PeerIndex, ephemeral:PublicKey, emptyTag:Tag) {
				self.typeHeader = 0x2
				self.initiatorIndex = initiatorIndex
				self.responderIndex = responderIndex
				self.ephemeral = ephemeral
				self.emptyTag = emptyTag
			}

			/// Computes `msg.mac1` for the receiver of this payload and appends the
			/// (all-zero) `msg.mac2` field, yielding an `Authenticated` response.
			/// - Parameter initiatorStaticPublicKey: The initiator's static public key.
			/// - Returns: The authenticated response message.
			/// - Throws: If key derivation or MAC computation fails.
			public borrowing func finalize(initiatorStaticPublicKey:UnsafePointer<PublicKey>) throws -> Authenticated {
				try withUnsafePointer(to:self) { selfPtr in
					// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
					var hasher = try WGHasher<Result.Bytes32>()
					try hasher.update([UInt8]("mac1----".utf8))
					try hasher.update(initiatorStaticPublicKey)
					let mac1 = try wgMAC(key:try hasher.finish(), data:selfPtr.pointee)
					
					// step 15: msg.mac2 := 0^16
					return Authenticated(payload:selfPtr.pointee, msgMac1: mac1, msgMac2:Result.Bytes16(RAW_staticbuff:Result.Bytes16.RAW_staticbuff_zeroed()))
				}
			}

			/// Builds a handshake response payload derived from the initiator's chain
			/// state. Use the `c` and `h` from the validated initiation.
			/// - Parameters:
			///   - cIn: The working chaining key from the initiation.
			///   - hIn: The working hash from the initiation.
			///   - initiatorPeerIndex: The initiator's peer index.
			///   - initiatorStaticPublicKey: The initiator's static public key.
			///   - initiatorEphemeralPublicKey: The initiator's ephemeral public key.
			///   - preSharedKey: The pre-shared key (may be all zeroes).
			///   - responderPeerIndex: The responder's peer index; a random one is
			///     generated when omitted.
			/// - Returns: The updated chain state and the forged payload.
			/// - Throws: If any cryptographic operation fails.
			public static func forge(c cIn:consuming Result.Bytes32, h hIn:consuming Result.Bytes32, initiatorPeerIndex:PeerIndex, initiatorStaticPublicKey:UnsafePointer<PublicKey>, initiatorEphemeralPublicKey: PublicKey, preSharedKey:MemoryGuarded<SharedKey>, responderPeerIndex:PeerIndex = try! generateSecureRandomBytes(as:PeerIndex.self)) throws -> (c:Result.Bytes32, h:Result.Bytes32, payload:Payload) {
				return try cIn.RAW_access_staticbuff_mutating { cPtr in
					return try hIn.RAW_access_staticbuff_mutating { hPtr in
						// step 1: (Epriv, Epub) := DH-GENERATE()
						let ephiPrivate = try MemoryGuarded<PrivateKey>.new()
						return try PublicKey(privateKey:ephiPrivate).RAW_access_staticbuff { ephiPublic in

							// step 2: c := KDF(c, Epub)
							cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2(Result.Bytes32.self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:ephiPublic, count:MemoryLayout<Result.Bytes32>.size)
							
							// step 4: h := HASH(h || msg.ephemeral)
							var hasher = try WGHasher<Result.Bytes32>()
							try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
							try hasher.update(ephiPublic, count:MemoryLayout<PublicKey>.size)
							hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()

							// step 5: c := KDF(c, DH(Epriv, initiatorEpub))
							try withUnsafePointer(to:initiatorEphemeralPublicKey) { ephiKeyPublic in
								cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2(Result.Bytes32.self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:ephiPrivate, publicKey: ephiKeyPublic.pointee))
							}
							
							// step 6: c := KDF(c, DH(Epriv, initiatorStaticPub))
							cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2(Result.Bytes32.self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey:ephiPrivate, publicKey: initiatorStaticPublicKey.pointee))

							// step 7: (c, T, k) := KDF^3(c, Q)
							var k:Result.Bytes32
							let T:Result.Bytes32
							(cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee, T, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:preSharedKey)
							
							// step 8: h := HASH(H || T)
							hasher = try WGHasher<Result.Bytes32>()
							try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
							try hasher.update(T)
							hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()

							// step 9: msg.empty := AEAD(k, 0, e, h)
							var e:[UInt8] = []
							let (_, emptyTag) = try aeadEncrypt(key:&k, counter:0, text:&e, aad:hPtr.assumingMemoryBound(to:Result.Bytes32.self))
							
							// step 10: h := HASH(h || msg.empty)
							hasher = try WGHasher<Result.Bytes32>()
							try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
							try hasher.update(emptyTag)
							hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()

							return (cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee, hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee, Payload(responderIndex:responderPeerIndex, initiatorIndex:initiatorPeerIndex, ephemeral:ephiPublic.assumingMemoryBound(to:PublicKey.self).pointee, emptyTag:emptyTag))
						}
					}
				}
			}
		}
	}
}

extension Message.Response.Payload {
	/// A handshake response message with MAC1 and MAC2 appended.
	@RAW_staticbuff(concat:Message.Response.Payload.self, Result.Bytes16.self, Result.Bytes16.self)
	public struct Authenticated:Sendable, Sequence {
		/// Errors that can occur while validating a response message.
		public enum Error:Swift.Error {
			/// The message's MAC1 did not match.
			case mac1Invalid
			/// The message's MAC2 did not match.
			case mac2Invalid
		}
		/// The underlying response payload.
		public let payload:Message.Response.Payload
		/// The message's MAC1.
		public let msgMac1:Result.Bytes16
		/// The message's MAC2.
		public let msgMac2:Result.Bytes16
		/// Creates an authenticated response message.
		public init(payload:Message.Response.Payload, msgMac1:Result.Bytes16, msgMac2:Result.Bytes16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}

		/// Validates the response given the initiator's chain state and keys.
		/// - Parameters:
		///   - cIn: The working chaining key from the initiation.
		///   - hIn: The working hash from the initiation.
		///   - initiatorStaticPrivateKey: The initiator's static private key.
		///   - initiatorEphemeralPrivateKey: The initiator's ephemeral private key.
		///   - preSharedKey: The pre-shared key (may be all zeroes).
		/// - Returns: The updated working chaining key and working hash.
		/// - Throws: `Error.mac1Invalid` if the MAC does not match, or any
		///   cryptographic operation fails.
		public borrowing func validate(c cIn:consuming Result.Bytes32, h hIn:consuming Result.Bytes32, initiatorStaticPrivateKey:MemoryGuarded<PrivateKey>, initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, preSharedKey:MemoryGuarded<SharedKey>) throws -> (c:Result.Bytes32, h:Result.Bytes32) {
			return try withUnsafePointer(to:self) { selfPtr in
				try cIn.RAW_access_staticbuff_mutating { cPtr in
					try hIn.RAW_access_staticbuff_mutating { hPtr in
						// setup: get responder public key
						let initiatorStaticPublicKey = PublicKey(privateKey:initiatorStaticPrivateKey)

						// step 0.5:
						let responderEphemeralPublicKey = selfPtr.pointer(to:\.payload.ephemeral)!.pointee

						// step 1: c := KDF(c, responderEpub)
						cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2((Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:responderEphemeralPublicKey)
						
						// step 4: h := HASH(h || msg.ephemeral)
						var hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(responderEphemeralPublicKey)
						hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()
						
						// step 5: c := KDF(c, DH(initiatorEpriv, responderEpub))
						cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2((Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey: initiatorEphemeralPrivateKey, publicKey:responderEphemeralPublicKey))
						
						// step 6: c := KDF(c, DH(initiatorStaticPrivateKey, responderEpub))
						cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try wgKDFv2((Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:try dhKeyExchange(privateKey: initiatorStaticPrivateKey, publicKey:responderEphemeralPublicKey))
						
						// step 7: (c, T, k) := KDF^3(c, Q)
						var k:Result.Bytes32
						var T:Result.Bytes32
						(cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee, T, k) = try wgKDFv2((Result.Bytes32, Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data: preSharedKey)
						
						// step 8: h := HASH(H || T)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(T)
						hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()
						
						// step 9: msg.empty := AEAD(k, 0, e, h)
						var e:[UInt8] = []
						_ = try aeadDecrypt(key:&k, counter:0, cipherText:&e, aad:hPtr.assumingMemoryBound(to:Result.Bytes32.self), tag:selfPtr.pointer(to:\.payload.emptyTag)!.pointee)

						// step 10: h := HASH(h || msg.empty)
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update(hPtr, count:MemoryLayout<Result.Bytes32>.size)
						try hasher.update(selfPtr.pointer(to:\.payload.emptyTag)!.pointee)
						hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee = try hasher.finish()
						
						// step 13: create MAC1
						hasher = try WGHasher<Result.Bytes32>()
						try hasher.update([UInt8]("mac1----".utf8))
						try hasher.update(initiatorStaticPublicKey)
						let mac1 = try wgMAC(key:try hasher.finish(), data: selfPtr.pointer(to: \.payload)!.pointee)
						guard mac1 == selfPtr.pointer(to:\.msgMac1)!.pointee else {
							throw Error.mac1Invalid
						}

						return (cPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee, hPtr.assumingMemoryBound(to:Result.Bytes32.self).pointee)
					}
				}
			}
		}
	}
}

import RAW
import RAW_dh25519
import RAW_chachapoly

/// defines the reserved field that follows the message type byte. these two items make up the first 4 bytes of any wireguard packet, unconditionally.
@RAW_staticbuff(bytes:3)
internal struct Reserved:Sendable {
	/// initializes a new Reserved
	internal init() {
		self = Self(RAW_staticbuff:[0, 0, 0])
	}
}

/// makes up the first 4 bytes of any wireguard packet, unconditionally.
@RAW_staticbuff(concat:RAW_byte.self, Reserved.self)
internal struct TypeHeading:Sendable, ExpressibleByIntegerLiteral {
	/// the type of packet
	internal let type:RAW_byte
	/// reserved bytes that follow the type byte
	internal let reserved:Reserved

	internal init(integerLiteral value:UInt8) {
		self.type = RAW_byte(RAW_native:value)
		self.reserved = Reserved()
	}

	/// validates that the type is a valid wireguard packet type and that the reserved bytes are all zero.
	/// - returns: true if the type is valid and the reserved bytes are all zero, false otherwise.
	internal func isValid() -> Bool {
		return reserved.RAW_access {
			guard $0[0] == 0 && $0[1] == 0 && $0[2] == 0 else {
				return false
			}
            switch type.RAW_native() {
				case 0x1, 0x2, 0x3, 0x4:
					return true
				default:
					return false
			}
		}
	}
}


internal struct HandshakeInitiationMessage:Sendable {
	internal static func forgeInitiationState(initiatorStaticPublicKey:UnsafePointer<PublicKey>, responderStaticPublicKey:UnsafePointer<PublicKey>) throws -> (c:Result32, h:Result32, k:Result32, payload:Payload) {
		// step 1: calculate the hash of the static construction string
		var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))

		// step 2: h = hash(ci || identifier)
		var hasher = try WGHasher()
		try hasher.update(c)
		try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
		var h = try hasher.finish()

		// step 3: h = hash(h || responderStaticPublicKey public key)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(responderStaticPublicKey)
		h = try hasher.finish()

		// step 4: generate ephemeral keys
		var ephiPrivate = try PrivateKey()
		let ephiPublic = PublicKey(&ephiPrivate)

		// step 5: c = KDF^1(c, e.Public)
		c =  try wgKDF(key:&c, data:ephiPublic, returning:(Result32).self)

		// step 6: assign e.Public to the ephemeral field
		let msgEphemeral = ephiPublic

		// step 7: h = hash(h | ephiPublic)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(ephiPublic)
		h = try hasher.finish()

		// step 8: (c, k) = KDF^2(c, dh(eiPriv, srPublic))
		var k:Result32
		(c, k) = try wgKDF(key:&c, data:try dhKeyExchange(privateKey:&ephiPrivate, publicKey:responderStaticPublicKey), returning:(Result32, Result32).self)

		// step 9: msg.static = AEAD(k, 0, siPublic, h)
		var (msgStatic, msgTag) = try aeadEncrypt(key:&k, counter:0, text:initiatorStaticPublicKey, aad:&h)

		// step 10: h = hash(h || msg.static)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(msgStatic)
		h = try hasher.finish()

		// step 11: c, k) = kdf^2(c, dh(sipriv, srpub))
		(c, k) = try wgKDF(key:&c, data:h, returning:(Result32, Result32).self)

		// step 12: msg.timestamp = AEAD(k, 0, timestamp(), h)
		var newTai = TAI64N()
		var (tsDat, tsTag) = try aeadEncrypt(key:&k, counter:0, text:&newTai, aad:&h)

		// step 13: h = hash(h || msg.timestamp)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(tsDat)
		h = try hasher.finish()

		return (c, h, k, Payload(initiatorPeerIndex:try generateSecureRandomBytes(as:PeerIndex.self), ephemeral:msgEphemeral, staticRegion:msgStatic, staticTag:msgTag, timestamp:tsDat, timestampTag:tsTag))
	}

	internal static func validateInitiationMessage(_ message:UnsafePointer<HandshakeInitiationMessage.Payload>, responderStaticPublicKey:PublicKey, responderStaticPrivateKey:UnsafePointer<PrivateKey>) throws -> Bool {
		// step 1: calculate the hash of the static construction string
		var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))

		// step 2: h = hash(ci || identifier)
		var hasher = try WGHasher()
		try hasher.update(c)
		try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
		var h = try hasher.finish()

		// step 3: h = hash(h || responderStaticPublicKey)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(responderStaticPublicKey)
		h = try hasher.finish()

		// step 4 - in the whitepaper this is when the ephemeral dh keypair is generated, but we (obviously) dont get that secret key here, so we read the public key from msg.ephemeral, which is where the initiator wrote it.
		var initiatorEphemeralPublicKey = message.pointee.ephemeral
	
		// step 5: c = KDF^1(c, initiatorEphemeralPublicKey)
		c =  try wgKDF(key:&c, data:initiatorEphemeralPublicKey, returning:(Result32).self)

		// step 6: h = hash(h || initiatorEphemeralPublicKey)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(initiatorEphemeralPublicKey)
		h = try hasher.finish()

		// step 7: (c, k) = KDF^2(c, dh(responderStaticPrivateKey, initiatorEphemeralPublicKey))
		var k:Result32
		(c, k) = try wgKDF(key:&c, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initiatorEphemeralPublicKey), returning:(Result32, Result32).self)

		// step 8: decrypt the msg.static to determine the initStaticPublicKey
		var initStaticPublicKey = try aeadDecrypt(key:&k, counter:0, cipherText:message.pointer(to:\.staticRegion)!, aad:&h, tag:message.pointee.staticTag)

		// step 9: h = hash(h || msg.static)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(initStaticPublicKey)
		h = try hasher.finish()

		// step 10: (c, k) = KDF^2(c, dh(msg.static [initiatorStaticPublicKey], responderStaticPrivateKey))
		(c, k) = try wgKDF(key:&c, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initStaticPublicKey), returning:(Result32, Result32).self)

		let sentTimestamp = try aeadDecrypt(key:&k, counter:0, cipherText:message.pointer(to:\.timestamp)!, aad:&h, tag:message.pointee.timestampTag)

		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(sentTimestamp)
		h = try hasher.finish()
        
        return true
	}

	/// this message is described in the wireguard whitepaper in section 5.4.2
    @RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PublicKey.self, PublicKey.self, Tag.self, TAI64N.self, Tag.self)
	internal struct Payload:Sendable {
		/// message type
		let typeHeader:TypeHeading
		/// initiator's peer index
		internal let initiatorPeerIndex:PeerIndex
		/// ephemeral key content
		internal let ephemeral:PublicKey
		/// static region of the message
		internal let staticRegion:PublicKey
		internal let staticTag:Tag
		/// timestamp associated with the message
		internal let timestamp:TAI64N
		internal let timestampTag:Tag

		/// initializes a new HandshakeInitiationMessage
		fileprivate init(initiatorPeerIndex:PeerIndex, ephemeral:PublicKey, staticRegion:PublicKey, staticTag:Tag, timestamp:TAI64N, timestampTag:Tag) {
			self.typeHeader = 0x1
			self.initiatorPeerIndex = initiatorPeerIndex
			self.ephemeral = ephemeral
			self.staticRegion = staticRegion
			self.staticTag = staticTag
			self.timestamp = timestamp
			self.timestampTag = timestampTag
		}
	}	
}

fileprivate struct HandshakeResponseMessage:Sendable {
	fileprivate struct Payload:Sendable {
        let typeHeader: TypeHeading
		let typeContent:RAW_byte
		let reservedContent:Reserved
		let senderIndex:PeerIndex
		let receiverIndex:PeerIndex
		let ephemeral:PublicKey
		let empty:Tag

		// init(receivingResponse:borrowing PeerIndex) throws {
		// 	typeContent = 0x2
		// 	let ephPrivate = try PrivateKey()
		// 	let ephPublic = PublicKey(ephPrivate)
		// 	// var cr = wgKDF(
		// }
	}
}

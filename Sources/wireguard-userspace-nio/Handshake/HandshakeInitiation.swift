import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
internal struct PeerIndex:Sendable {
	internal static func random() throws -> Self {
		return try generateSecureRandomBytes(as:Self.self)
	}
}

/// defines the reserved field that follows the message type byte. these two items make up the first 4 bytes of any wireguard packet, unconditionally.
@RAW_staticbuff(bytes:3)
internal struct Reserved:Sendable {
	/// initializes a new Reserved
	internal init() {
		self = Self(RAW_staticbuff:[0, 0, 0])
	}
	internal func isValid() -> Bool {
		return RAW_access { $0[0] == 0 && $0[1] == 0 && $0[2] == 0 }
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
		guard reserved.isValid() == true else {
			return false
		}
		switch type.RAW_native() {
			case 0x1, 0x2, 0x3, 0x4:
				return true
			default:
				return false
		}
	}

	/// compares the type heading to a UInt8 value.
	/// - parameter lhs: the type heading to compare
	/// - parameter rhs: the UInt8 value to compare against
	/// - returns: true if the type heading's type matches the UInt8 value, false otherwise.
	/// - NOTE: this function does not concern itself with the reserved bytes, only the type byte.
	internal static func == (lhs:TypeHeading, rhs:UInt8) -> Bool {
		return lhs.type.RAW_native() == rhs
	}
}

internal struct HandshakeInitiationMessage {
	internal static func forgeInitiationState(initiatorStaticPrivateKey:UnsafePointer<PrivateKey>, responderStaticPublicKey:UnsafePointer<PublicKey>) throws -> (c:Result32, h:Result32, k:Result32, payload:Payload) {
		// step 0: get initiator public key
		var initiatorStaticPublicKey = PublicKey(initiatorStaticPrivateKey)

		// step 1: calculate the hash of the static construction string
		var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))

		// step 2: h = hash(ci || identifier)
		var hasher = try WGHasher()
		try hasher.update(c)
		try hasher.update([UInt8]("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
		var h = try hasher.finish()

		// step 3: h = hash(h || responderStaticPublicKey public key)
		hasher = try WGHasher()
		try hasher.update(&h)
		try hasher.update(responderStaticPublicKey)
		h = try hasher.finish()

		// step 4: generate ephemeral keys
		var ephiPrivate = try PrivateKey()
		let ephiPublic = PublicKey(&ephiPrivate)

		// step 5: c = KDF^1(c, e.Public)
		c =  try wgKDF(key:c, data:ephiPublic, type:1)[0]

		// step 6: assign e.Public to the ephemeral field
		let msgEphemeral = ephiPublic

		// step 7: h = hash(h | ephiPublic)
		hasher = try WGHasher()
		try hasher.update(&h)
		try hasher.update(ephiPublic)
		h = try hasher.finish()

		// step 8: (c, k) = KDF^2(c, dh(eiPriv, srPublic))
		var k:Result32
		var arr:[Result32]
		arr = try wgKDF(key:c, data:try dhKeyExchange(privateKey:&ephiPrivate, publicKey:responderStaticPublicKey), type:2)
		c = arr[0]; k = arr[1]

		// step 9: msg.static = AEAD(k, 0, siPublic, h)
		let (msgStatic, msgTag) = try aeadEncrypt(key:k, counter:0, text:&initiatorStaticPublicKey, aad:&h)

		// step 10: h = hash(h || msg.static)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(msgStatic)
		try hasher.update(msgTag)
		h = try hasher.finish()

		// step 11: c, k) = kdf^2(c, dh(sipriv, srpub))
		arr = try wgKDF(key:c, data:try dhKeyExchange(privateKey:initiatorStaticPrivateKey, publicKey:responderStaticPublicKey), type:2)
		c = arr[0]; k = arr[1]

		// step 12: msg.timestamp = AEAD(k, 0, timestamp(), h)
		let (tsDat, tsTag) = try withUnsafePointer(to:TAI64N()) { taiPtr in
			return try aeadEncrypt(key:k, counter:0, text:taiPtr, aad:&h)
		}
		// step 13: h = hash(h || msg.timestamp)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(tsDat)
		try hasher.update(tsTag)
		h = try hasher.finish()
		
		return (c, h, k, Payload(initiatorPeerIndex:try generateSecureRandomBytes(as:PeerIndex.self), ephemeral:msgEphemeral, staticRegion:msgStatic, staticTag:msgTag, timestamp:tsDat, timestampTag:tsTag))
	}

	internal static func finalizeInitiationState(responderStaticPublicKey:UnsafePointer<PublicKey>, payload:consuming Payload) throws -> AuthenticatedPayload {		
		// step 14: msg.mac1 := MAC(HASH(LABEL-MAC1 || Spub(m')), msga)
		var hasher = try WGHasher()
		try hasher.update([UInt8]("mac1----".utf8))
		try hasher.update(responderStaticPublicKey)
		let mac1 = try wgMac(key:try hasher.finish(), data:copy payload)
		
		// step 15: msg.mac2 := 0^16
		var mac2 = Result16(RAW_staticbuff:Result16.RAW_staticbuff_zeroed())

		return AuthenticatedPayload(payload:payload, msgMac1: mac1, msgMac2: mac2)        
	}
	
	/// thrown when a handshake initiation message is received but does not contain the expected type heading.
	internal struct InvalidTypeHeadingError:Swift.Error {}
	/// thrown when a handshake initiation message is received but does not contain a valid MAC1.
	internal struct MAC1InvalidError:Swift.Error {}
	internal static func validateInitiationMessage(_ message:UnsafePointer<HandshakeInitiationMessage.AuthenticatedPayload>, responderStaticPrivateKey:UnsafePointer<PrivateKey>) throws -> (c:Result32, h:Result32, k:Result32, initPublicKey:PublicKey, timestamp:TAI64N) {
		guard message.pointer(to:\.payload.typeHeader)!.pointee.isValid() == true else {
			throw HandshakeInitiationMessage.InvalidTypeHeadingError()
		}

		// step 0: get responder public key
		let responderStaticPublicKey = PublicKey(responderStaticPrivateKey)
		
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

		// step 3.5 - store the initiators ephemeral key
		var initiatorEphemeralPublicKey = message.pointer(to:\.payload.ephemeral)!.pointee

		// step 5: c = KDF^1(c, initiatorEphemeralPublicKey)
		c =  try wgKDF(key:c, data:initiatorEphemeralPublicKey, type:1)[0]

		// step 6: h = hash(h || initiatorEphemeralPublicKey)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(initiatorEphemeralPublicKey)
		h = try hasher.finish()

		// step 7: (c, k) = KDF^2(c, dh(responderStaticPrivateKey, initiatorEphemeralPublicKey))
		var k:Result32
		var arr:[Result32]
		arr = try wgKDF(key:c, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initiatorEphemeralPublicKey), type:2)
		c = arr[0]; k = arr[1]

		// step 8: decrypt the msg.static to determine the initStaticPublicKey
		var initStaticPublicKey = try aeadDecrypt(key:k, counter:0, cipherText:message.pointer(to:\.payload.staticRegion)!, aad:&h, tag:message.pointer(to:\.payload.staticTag)!.pointee)
		
		let publickey = String(try RAW_base64.encode(initStaticPublicKey))
	
		// step 9: h = hash(h || msg.static)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(message.pointee.payload.staticRegion)
		try hasher.update(message.pointee.payload.staticTag)
		h = try hasher.finish()

		// step 10: (c, k) = KDF^2(c, dh(msg.static [initiatorStaticPublicKey], responderStaticPrivateKey))
		arr = try wgKDF(key:c, data:try dhKeyExchange(privateKey:responderStaticPrivateKey, publicKey:&initStaticPublicKey), type:2)
		c = arr[0]; k = arr[1]

		// step 11: descrypt the msg.timestamp to find the intial timestamp
		let sentTimestamp = try aeadDecrypt(key:k, counter:0, cipherText:message.pointer(to:\.payload.timestamp)!, aad:&h, tag:message.pointee.payload.timestampTag)

		// step 12: h = hash(h || msg.static)
		hasher = try WGHasher()
		try hasher.update(h)
		try hasher.update(message.pointee.payload.timestamp)
		try hasher.update(message.pointee.payload.timestampTag)
		h = try hasher.finish()
		
		// step 13: create MAC1
		hasher = try WGHasher()
		try hasher.update([UInt8]("mac1----".utf8))
		try hasher.update(responderStaticPublicKey)
		let mac1 = try wgMac(key:try hasher.finish(), data: message.pointee.payload)
		
		guard mac1 == message.pointee.msgMac1 else {
			throw MAC1InvalidError()
		}
		
		return (c, h, k, initStaticPublicKey, sentTimestamp)
	}

	/// this message is described in the wireguard whitepaper in section 5.4.2
	@RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, PublicKey.self, PublicKey.self, Tag.self, TAI64N.self, Tag.self)
	internal struct Payload:Sendable {
		/// message type
		internal let typeHeader:TypeHeading
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
	
	@RAW_staticbuff(concat:Payload.self, Result16.self, Result16.self)
	internal struct AuthenticatedPayload:Sendable, Sequence {
		internal let payload:Payload
		internal let msgMac1:Result16
		internal let msgMac2:Result16
		fileprivate init(payload:Payload, msgMac1:Result16, msgMac2:Result16) {
			self.payload = payload
			self.msgMac1 = msgMac1
			self.msgMac2 = msgMac2
		}
	}
}

fileprivate struct HandshakeResponseMessage:Sendable {
	fileprivate struct Payload:Sendable {
        internal let typeHeader: TypeHeading
		internal let typeContent:RAW_byte
		internal let reservedContent:Reserved
		internal let senderIndex:PeerIndex
		internal let receiverIndex:PeerIndex
		internal let ephemeral:PublicKey
		internal let empty:Tag
	}
}

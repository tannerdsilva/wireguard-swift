import Testing
@testable import wireguard_userspace_nio
import RAW_dh25519
import RAW_base64
import RAW_xchachapoly
import RAW
import NIO
import wireguard_crypto_core

@Test func testCreateInitilizationMessage() throws {
    let staticPublicKey = try dhGenerate()
    let peerPublicKey = try dhGenerate().0
    
    let (_, _, _, payload) = try withUnsafePointer(to: staticPublicKey.1) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try Message.Initiation.Payload.forge(initiatorStaticPrivateKey: p, responderStaticPublicKey: q)
        }
    }
    
    let _ = try withUnsafePointer(to: staticPublicKey) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try payload.finalize(responderStaticPublicKey: q)
        }
    }
}

@Test func countedNonceSortTest() throws {
	let nonce1 = CountedNonce(integerLiteral:1)
	let nonce2 = CountedNonce(integerLiteral:2)
	let nonce3 = nonce2 + 1
	
	#expect(nonce1 < nonce2)
	#expect(nonce2 < nonce3)
	#expect(nonce3 > nonce1)
}

@Test func selfValidateInitiation() throws {
	var initiatorPrivateKey = try PrivateKey()
	var initiatorPublicKey = PublicKey(privateKey:&initiatorPrivateKey)
	var responderStaticPrivateKey = try PrivateKey()
	var responderStaticPublicKey = PublicKey(privateKey:&responderStaticPrivateKey)
	var constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
	let responderValidationStep = try authenticatedPacketToSend.validate(responderStaticPrivateKey: &responderStaticPrivateKey)
}

@Test func selfValidateResponse() throws {
    var initiatorPrivateKey = try PrivateKey()
    var initiatorPublicKey = PublicKey(privateKey:&initiatorPrivateKey)
    var initiatorEphemeralPrivateKey = try PrivateKey()
    var initiatorEphemeralPublicKey = PublicKey(privateKey:&initiatorEphemeralPrivateKey)
    var sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()) // 0^32 shared key default
    var senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
    var constructedPacket = try Message.Response.Payload.forge(c: sharedKey, h: sharedKey, initiatorPeerIndex: senderIndex, initiatorStaticPublicKey: &initiatorPublicKey, initiatorEphemeralPublicKey: initiatorEphemeralPublicKey, preSharedKey: sharedKey)
    var authenticatedPacket = try constructedPacket.payload.finalize(initiatorStaticPublicKey: &initiatorPublicKey)
    let responseValidationStep = try authenticatedPacket.validate(c:sharedKey, h:sharedKey, initiatorStaticPrivateKey: &initiatorPrivateKey, initiatorEphemeralPrivateKey: &initiatorEphemeralPrivateKey, preSharedKey: sharedKey)
}

@Test func selfValidateDataPacket() throws {
	try Result32(RAW_staticbuff: try generateRandomBytes(count: 32)).RAW_access_staticbuff { cPtr in
		let (TIsend, _) = try wgKDFv2((Result32, Result32).self, key: cPtr, count:MemoryLayout<Result32>.size, data: [] as [UInt8], count:0)
		let (TRrecv, _) = try wgKDFv2((Result32, Result32).self, key: cPtr, count:MemoryLayout<Result32>.size, data: [] as [UInt8], count:0)

		let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
		
		let message:String = "This is a message to be encrypted"
		let messageBytes: [UInt8] = Array(message.utf8)
		var nonce_i:Counter = Counter(RAW_native: 0)
		
		var encryptedPacket = try Message.Data.Payload.forge(receiverIndex: senderIndex, nonce: &nonce_i, transportKey: TIsend, plainText: messageBytes)
		
		var nonce_r:Counter = Counter(RAW_native: 0)

		let decryptedPacket = try encryptedPacket.decrypt(transportKey: TRrecv)
		if let recoveredMessage = String(bytes: decryptedPacket, encoding: .utf8) {
			print("Recovered message: '\(recoveredMessage) @ \(recoveredMessage.count) bytes'")
			print("Original message: '\(message)' @ \(message.count) bytes'")
			#expect(recoveredMessage == message)
		} else {
			struct InvalidUTF8Error:Swift.Error {}
			throw InvalidUTF8Error()
		}
	}
}

@Test func selfValidateCookiePacket() throws {
	var initiatorPrivateKey = try PrivateKey()
	
	var initiatorPublicKey = PublicKey(privateKey:&initiatorPrivateKey)
	
	var responderStaticPrivateKey = try PrivateKey()
	
	var responderStaticPublicKey = PublicKey(privateKey:&responderStaticPrivateKey)
	
	// Pre-computing HASH(LABEL-COOKIE || Spub)
	var hasher = try! WGHasherV2<RAW_xchachapoly.Key>()
	try! hasher.update([UInt8]("cookie--".utf8))
	try! hasher.update(responderStaticPublicKey)
	let precomputedCookieKey = try! hasher.finish()
	
	var constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
	let endpoint = try SocketAddress(ipAddress: "192.0.2.1", port: 51820)
	let secretCookieR = try! generateSecureRandomBytes(as:Result8.self)
	let cookie = try Message.Cookie.Payload.forge(receiverPeerIndex: authenticatedPacketToSend.payload.initiatorPeerIndex, k: precomputedCookieKey, r: secretCookieR, a: endpoint, m: authenticatedPacketToSend.msgMac1)

	authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey, cookie: cookie)

	try authenticatedPacketToSend.validateUnderLoad(responderStaticPrivateKey: &responderStaticPrivateKey, R: secretCookieR, A: endpoint)
}

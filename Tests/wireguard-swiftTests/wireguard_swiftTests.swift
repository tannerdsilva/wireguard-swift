import Testing
@testable import wireguard_userspace_nio
import RAW_dh25519
import RAW_base64
import RAW_xchachapoly
import RAW
import NIO

@Test func testCreateInitilizationMessage() throws {
    let staticPublicKey = try dhGenerate()
    let peerPublicKey = try dhGenerate().0
    
    let (_,_,_,payload) = try withUnsafePointer(to: staticPublicKey.1) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: p, responderStaticPublicKey: q)
        }
    }
    
    let _ = try withUnsafePointer(to: staticPublicKey) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: q, payload: payload)
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
	var constructedPacket = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: &responderStaticPublicKey, payload: constructedPacket.payload)
	let responderValidationStep = try HandshakeInitiationMessage.validateInitiationMessage(&authenticatedPacketToSend, responderStaticPrivateKey: &responderStaticPrivateKey)
}

@Test func selfValidateResponse() throws {
    var initiatorPrivateKey = try PrivateKey()
    var initiatorPublicKey = PublicKey(privateKey:&initiatorPrivateKey)
    var initiatorEphemeralPrivateKey = try PrivateKey()
    var initiatorEphemeralPublicKey = PublicKey(privateKey:&initiatorEphemeralPrivateKey)
    var sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()) // 0^32 shared key default
    var senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
    var constructedPacket = try HandshakeResponseMessage.forgeResponseState(c: sharedKey, h: sharedKey, initiatorPeerIndex: senderIndex, initiatorStaticPublicKey: &initiatorPublicKey, initiatorEphemeralPublicKey: initiatorEphemeralPublicKey, preSharedKey: sharedKey)
    var authenticatedPacket = try HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &initiatorPublicKey, payload: constructedPacket.payload)
    let responseValidationStep = try HandshakeResponseMessage.validateResponseMessage(c: sharedKey, h: sharedKey, message: &authenticatedPacket, initiatorStaticPrivateKey: &initiatorPrivateKey, initiatorEphemeralPrivateKey: &initiatorEphemeralPrivateKey, preSharedKey: sharedKey)
}

@Test func selfValidateDataPacket() throws {
    let c: Result32 = Result32(RAW_staticbuff: try generateRandomBytes(count: 32))
    let e:[UInt8] = []
    let arr_send:[Result32] = try wgKDF(key: c, data: e, type: 2)
    let arr_recv:[Result32] = try wgKDF(key: c, data: e, type: 2)
    let TIsend = arr_send[0]
    let TRrecv = arr_recv[0]
    
    let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
    
    let message:String = "This is a message to be encrypted"
    let messageBytes: [UInt8] = Array(message.utf8)
    var nonce_i:Counter = Counter(RAW_native: 0)
    
    var encryptedPacket = try DataMessage.forgeDataMessage(receiverIndex: senderIndex, nonce: &nonce_i, transportKey: TIsend, plainText: messageBytes)
    
    var nonce_r:Counter = Counter(RAW_native: 0)
    
    let decryptedPacket = try DataMessage.decryptDataMessage(&encryptedPacket, transportKey: TRrecv)
    if let recoveredMessage = String(bytes: decryptedPacket, encoding: .utf8) {
		print("Recovered message: '\(recoveredMessage) @ \(recoveredMessage.count) bytes'")
		print("Original message: '\(message)' @ \(message.count) bytes'")
		#expect(recoveredMessage == message)
    } else {
        struct InvalidUTF8Error:Swift.Error {}
        throw InvalidUTF8Error()
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
	
	var constructedPacket = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: &responderStaticPublicKey, payload: constructedPacket.payload)
	let endpoint = try SocketAddress(ipAddress: "192.0.2.1", port: 51820)
	let secretCookieR = try! generateSecureRandomBytes(as:Result8.self)
	let cookie = try CookieReplyMessage.forgeCookieReply(receiverPeerIndex: authenticatedPacketToSend.payload.initiatorPeerIndex, k: precomputedCookieKey, R: secretCookieR, A: endpoint, M: authenticatedPacketToSend.msgMac1)
	
	authenticatedPacketToSend = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: &responderStaticPublicKey, payload: constructedPacket.payload, cookie: cookie)
	
	let (mac1Valid, mac2Valid) = try HandshakeInitiationMessage.validateUnderLoad([authenticatedPacketToSend], responderStaticPrivateKey: &responderStaticPrivateKey, R: secretCookieR, A: endpoint)
	
	#expect(mac1Valid)
	#expect(mac2Valid)
}

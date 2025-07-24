import Testing
@testable import wireguard_userspace_nio
import RAW_dh25519
import RAW_base64
import RAW

@Test func testCreateInitilizationMessage() throws {
    let staticPublicKey = try dhGenerate()
    let peerPublicKey = try dhGenerate().0
    
    let (_,_,payload) = try withUnsafePointer(to: staticPublicKey.1) { p in
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

@Test func selfValidateInitiation() throws {
	var initiatorPrivateKey = try PrivateKey()
	var initiatorPublicKey = PublicKey(&initiatorPrivateKey)
	var responderStaticPrivateKey = try PrivateKey()
	var responderStaticPublicKey = PublicKey(&responderStaticPrivateKey)
	var constructedPacket = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: &responderStaticPublicKey, payload: constructedPacket.payload)
	let responderValidationStep = try HandshakeInitiationMessage.validateInitiationMessage(&authenticatedPacketToSend, responderStaticPrivateKey: &responderStaticPrivateKey)
}

@Test func selfValidateResponse() throws {
    var initiatorPrivateKey = try PrivateKey()
    var initiatorPublicKey = PublicKey(&initiatorPrivateKey)
    var initiatorEphemeralPrivateKey = try PrivateKey()
    var initiatorEphemeralPublicKey = PublicKey(&initiatorEphemeralPrivateKey)
    var sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()) // 0^32 shared key default
    var senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
    var constructedPacket = try HandshakeResponseMessage.forgeResponseState(senderPeerIndex: senderIndex, initiatorStaticPublicKey: &initiatorPublicKey, initiatorEphemeralPublicKey: &initiatorEphemeralPublicKey, preSharedKey: sharedKey)
    var authenticatedPacket = try HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &initiatorPublicKey, payload: constructedPacket.payload)
    let responseValidationStep = try HandshakeResponseMessage.validateResponseMessage(&authenticatedPacket, initiatorStaticPrivateKey: &initiatorPrivateKey, initiatorEphemeralPrivateKey: &initiatorEphemeralPrivateKey, preSharedKey: sharedKey)
}

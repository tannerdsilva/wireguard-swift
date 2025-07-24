import Testing
@testable import wireguard_userspace_nio
import RAW_dh25519
import RAW_base64

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

@Test func selfValidate() throws {
	var initiatorPrivateKey = try PrivateKey()
	var initiatorPublicKey = PublicKey(&initiatorPrivateKey)
	var responderStaticPrivateKey = try PrivateKey()
	var responderStaticPublicKey = PublicKey(&responderStaticPrivateKey)
	var constructedPacket = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: &initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
	var authenticatedPacketToSend = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: &responderStaticPublicKey, payload: constructedPacket.payload)
	let responderValidationStep = try HandshakeInitiationMessage.validateInitiationMessage(&authenticatedPacketToSend, responderStaticPrivateKey: &responderStaticPrivateKey)
}
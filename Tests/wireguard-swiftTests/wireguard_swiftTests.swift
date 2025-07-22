import Testing
@testable import wireguard_userspace_nio

@Test func testCreateInitilizationMessage() throws {
    let staticPublicKey = try dhGenerate().0
    let peerPublicKey = try dhGenerate().0
    
    var (_,_,_,payload) = try withUnsafePointer(to: staticPublicKey) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPublicKey: p, responderStaticPublicKey: q)
        }
    }
    
    var authenticatedPayload = try withUnsafePointer(to: staticPublicKey) { p in
        try withUnsafePointer(to: peerPublicKey) { q in
            return try HandshakeInitiationMessage.finalizeInitiationState(initiatorStaticPublicKey: p, responderStaticPublicKey: q, payload: payload)
        }
    }
}


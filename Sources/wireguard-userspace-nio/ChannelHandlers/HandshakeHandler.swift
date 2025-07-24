import NIO
import RAW_dh25519

internal final class HandshakeHandler:ChannelDuplexHandler, Sendable {
    typealias InboundIn = PacketType
    typealias InboundOut = PacketType

    typealias OutboundIn = HandshakeInitiationInvoke
    typealias OutboundOut = PacketType
    
    let privateKey:PrivateKey
    
    init(privateKey:consuming PrivateKey) {
        self.privateKey = privateKey
    }

	// func sendHandshake(to endpoint:SocketAddress, expectedPeerPublicKey:PublicKey) {
		// withUnsafePointer(to:privateKey) { privateKey in
		// 	try withUnsafePointer(to:expectedPeerPublicKey) { expectedPeerPublicKey in
		// 		let payload = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
		// 		let authenticatedPacket = try! HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload: payload.payload)
		// 		let packet: PacketType = .handshakeInitiation(endpoint, authenticatedPacket)
				
		// 	}
		// }
	// }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        /// Handles Handshake Packets, else passes them down
        let packet = self.unwrapInboundIn(data)
        withUnsafePointer(to:privateKey) { responderPrivateKey in
			switch packet {
				case var .handshakeInitiation(endpoint, payload):
					/// Reads initiation payload and validates it.
					/// Once validated, sends a response packet
					var val = try! HandshakeInitiationMessage.validateInitiationMessage(&payload, responderStaticPrivateKey: responderPrivateKey)
					var sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed())
					var response = try! HandshakeResponseMessage.forgeResponseState(cInput:val.c, hInput:val.h, initiatorPeerIndex: payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey: payload.payload.ephemeral, preSharedKey: sharedKey)
					let authResponse = try! HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &val.initPublicKey, payload: response.payload)
					let packet: PacketType = .handshakeResponse(endpoint, authResponse)
					
					context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess {
						print("Handshake response sent to \(endpoint)")
					}
					
				case let .handshakeResponse(endpoint, payload):
					/// Reads response packet and validates it.
					/// Once validated, updates keys for data encryption (NEEDS COMPLETION)
					print("nothing")
				default:
					context.fireChannelRead(wrapInboundOut(packet))
			}
		}
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
       let invoke = self.unwrapOutboundIn(data)
	   try! withUnsafePointer(to:privateKey) { privateKey in
			try withUnsafePointer(to:invoke.publicKey) { expectedPeerPublicKey in
				let payload = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
				let authenticatedPacket = try! HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload: payload.payload)
				let packet: PacketType = .handshakeInitiation(invoke.endpoint, authenticatedPacket)
				context.writeAndFlush(self.wrapOutboundOut(packet), promise: promise)
			}
		}
    }
}

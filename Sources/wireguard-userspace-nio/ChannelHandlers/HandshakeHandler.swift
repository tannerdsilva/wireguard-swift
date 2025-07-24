import NIO
import RAW_dh25519

internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = PacketType
    typealias InboundOut = PacketType

    typealias OutboundIn = HandshakeInitiationInvoke
    typealias OutboundOut = PacketType
    
    let privateKey:PrivateKey

	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
    
    init(privateKey:consuming PrivateKey) {
        self.privateKey = privateKey
    }

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
					
				case var .handshakeResponse(endpoint, payload):
					guard let initiatorEphiPrivateKey = initiatorEphemeralPrivateKey[payload.payload.initiatorIndex] else {
						print("Received handshake response for unknown peer index \(payload.payload.initiatorIndex)")
						return
					}
					withUnsafePointer(to:privateKey) { myPrivateKeyPointer in
						withUnsafePointer(to:initiatorEphiPrivateKey) { initiatorStaticPrivateKeyPtr in
							let val = try! HandshakeResponseMessage.validateResponseMessage(&payload, initiatorStaticPrivateKey:myPrivateKeyPointer, initiatorEphemeralPrivateKey:initiatorStaticPrivateKeyPtr, preSharedKey:Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()))
						}
					}
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
				initiatorEphemeralPrivateKey[authenticatedPacket.payload.initiatorPeerIndex] = payload.ephiPrivateKey
				let packet: PacketType = .handshakeInitiation(invoke.endpoint, authenticatedPacket)
				context.writeAndFlush(self.wrapOutboundOut(packet), promise: promise)
			}
		}
	}
}

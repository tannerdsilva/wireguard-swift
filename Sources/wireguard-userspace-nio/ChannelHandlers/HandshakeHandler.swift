import NIO
import RAW_dh25519
import Logging

/// handles the handshakes for the WireGuard protocol.
/// - NOTE: this handler is marked as `@unchecked Sendable` because it trusts NIO event loops to manage its internal state correctly
internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PacketType
	internal typealias InboundOut = PacketType

	internal typealias OutboundIn = HandshakeInitiationInvoke
	internal typealias OutboundOut = PacketType
	
	private let logger:Logger
	internal let privateKey:PrivateKey

	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result32, h:Result32)] = [:]
	
	init(privateKey:consuming PrivateKey, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		self.logger = buildLogger
		self.privateKey = privateKey
	}

	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif

		// handles handshake packets, else passes them down
		do {
			try withUnsafePointer(to:privateKey) { responderPrivateKey in
				switch unwrapInboundIn(data) {
					case let .handshakeInitiation(endpoint, payload):
						
						var val = try HandshakeInitiationMessage.validateInitiationMessage([payload], responderStaticPrivateKey: responderPrivateKey)
						let sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed())
						var response = try HandshakeResponseMessage.forgeResponseState(cInput:val.c, hInput:val.h, initiatorPeerIndex: payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey)
						let authResponse = try HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &val.initPublicKey, payload:response.payload)
						let packet: PacketType = .handshakeResponse(endpoint, authResponse)
						
						context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess { [ep = endpoint] in
							print("Handshake response sent to \(ep)")
						}
						
					case var .handshakeResponse(endpoint, payload):
						guard let initiatorEphiPrivateKey = initiatorEphemeralPrivateKey[payload.payload.initiatorIndex] else {
							print("Received handshake response for unknown peer index \(payload.payload.initiatorIndex)")
							return
						}
						guard let (existingC, existingH) = initiatorChainingData[payload.payload.initiatorIndex] else {
							print("Received handshake response for unknown peer index \(payload.payload.initiatorIndex)")
							return
						}
						try withUnsafePointer(to:privateKey) { myPrivateKeyPointer in
							try withUnsafePointer(to:initiatorEphiPrivateKey) { initiatorStaticPrivateKeyPtr in
								let val = try HandshakeResponseMessage.validateResponseMessage(c:existingC, h:existingH, message:&payload, initiatorStaticPrivateKey:myPrivateKeyPointer, initiatorEphemeralPrivateKey:initiatorStaticPrivateKeyPtr, preSharedKey:Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()))
								logger.info("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.initiatorIndex)"])
							}
						}
					default:
						return
						// context.fireChannelRead(wrapInboundOut(packet))
				}
			}
		} catch let error {
			logger.error("error processing handshake packet: \(error)")
			context.fireErrorCaught(error)
		}
	}
	
	func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif

		let invoke = unwrapOutboundIn(data)
		do {
			try withUnsafePointer(to:privateKey) { privateKey in
				try withUnsafePointer(to:invoke.publicKey) { expectedPeerPublicKey in
					let (c, h, ephiPrivateKey, payload) = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
					initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
					initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
					logger.debug("successfully forged handshake initiation message", metadata:["peer_endpoint":"\(invoke.endpoint.description)", "peer_public_key":"\(invoke.publicKey.debugDescription)"])
					context.writeAndFlush(wrapOutboundOut(PacketType.handshakeInitiation(invoke.endpoint, try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload:payload))), promise:promise)
				}
			}
		} catch let error {
			context.fireErrorCaught(error)
			promise?.fail(error)
		}
	}
}

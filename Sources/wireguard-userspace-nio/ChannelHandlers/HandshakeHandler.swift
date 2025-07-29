import NIO
import RAW_dh25519
import Logging

/// handles the handshakes for the WireGuard protocol.
/// - NOTE: this handler is marked as `@unchecked Sendable` because it trusts NIO event loops to manage its internal state correctly
internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PacketType
	internal typealias InboundOut = PacketType

	internal typealias OutboundIn = PacketType
	internal typealias OutboundOut = PacketType
	
	private let logger:Logger
	internal let privateKey:PrivateKey
    internal let peers:[SocketAddress:PublicKey]

	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result32, h:Result32)] = [:]
	
	internal init(privateKey:consuming PrivateKey, peers: [SocketAddress:PublicKey], logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		self.logger = buildLogger
		self.privateKey = privateKey
        self.peers = peers
	}

	internal borrowing func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif

		// handles handshake packets, else passes them down
		do {
			try withUnsafePointer(to:privateKey) { responderPrivateKey in
				switch unwrapInboundIn(data) {
					case .handshakeInitiation(let endpoint, let payload):
						logger.debug("received handshake initiation packet", metadata:["remote_address":"\(endpoint.description)"])
						var val = try HandshakeInitiationMessage.validateInitiationMessage([payload], responderStaticPrivateKey: responderPrivateKey)
						let sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed())
						let response = try HandshakeResponseMessage.forgeResponseState(c:val.c, h:val.h, initiatorPeerIndex: payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey)
						let authResponse = try HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &val.initPublicKey, payload:response.payload)
						let packet: PacketType = .handshakeResponse(endpoint, authResponse)
						
						context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess { [ep = endpoint] in
							print("Handshake response sent to \(ep)")
						}
                        
                        /// Pass data for creating transit keys
                        let keyPacket: PacketType = .keyExchange(endpoint, response.payload.responderIndex, response.c, false)
                        logger.debug("Sending key exhange packet to data handler")
                        context.fireChannelRead(wrapInboundOut(keyPacket))
						
					case .handshakeResponse(let endpoint, var payload):
						logger.debug("received handshake response packet", metadata:["remote_address":"\(endpoint.description)"])
						guard let initiatorEphiPrivateKey = initiatorEphemeralPrivateKey[payload.payload.initiatorIndex] else {
							logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
							return
						}
						guard let (existingC, existingH) = initiatorChainingData[payload.payload.initiatorIndex] else {
							logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing chaining data")
							return
						}
						try withUnsafePointer(to:privateKey) { myPrivateKeyPointer in
							try withUnsafePointer(to:initiatorEphiPrivateKey) { initiatorEphiPrivateKeyPtr in
								let val = try HandshakeResponseMessage.validateResponseMessage(c:existingC, h:existingH, message:&payload, initiatorStaticPrivateKey:myPrivateKeyPointer, initiatorEphemeralPrivateKey:initiatorEphiPrivateKeyPtr, preSharedKey:Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()))
								logger.info("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.initiatorIndex)"])
                                
                                /// Pass data for creating transit keys
                                let packet: PacketType = .keyExchange(endpoint, payload.payload.responderIndex, val.c, true)
                                logger.debug("Sending key exhange packet to data handler")
                                context.fireChannelRead(wrapInboundOut(packet))
							}
						}
                    case .transit(let endpoint, let payload):
                        logger.debug("Data transit packet sent to data handler")
                        context.fireChannelRead(wrapInboundOut(PacketType.transit(endpoint, payload)))
					default:
						return
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
		
        switch invoke {
            case let .initiationInvoker(endpoint):
                do {
                    print("Peerss: \(peers)")
                    guard let peerPublicKey = peers[endpoint] else {
                        logger.debug("Peer for endpoint \(endpoint) not found")
                        return
                    }
                    try withUnsafePointer(to:privateKey) { privateKey in
                        try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
                            let (c, h, ephiPrivateKey, payload) = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
                            initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
                            initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
                            logger.debug("successfully forged handshake initiation message", metadata:["peer_endpoint":"\(endpoint.description)", "peer_public_key":"\(peerPublicKey.debugDescription)"])
                            context.writeAndFlush(wrapOutboundOut(PacketType.handshakeInitiation(endpoint, try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload:payload))), promise:promise)
                        }
                    }
                } catch let error {
                    context.fireErrorCaught(error)
                    promise?.fail(error)
                }
            case .transit(let endpoint, let payload):
                logger.debug("Sending transit packout down to packet handler")
                context.writeAndFlush(wrapOutboundOut(PacketType.transit(endpoint, payload)), promise:promise)
            default:
                return
        }
	}
}

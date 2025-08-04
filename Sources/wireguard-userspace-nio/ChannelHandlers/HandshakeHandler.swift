import NIO
import RAW_dh25519
import Logging
import RAW

// handles the handshakes for the WireGuard protocol.
// - NOTE: this handler is marked as `@unchecked Sendable` because it trusts NIO event loops to manage its internal state correctly
internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PacketType
	internal typealias InboundOut = PacketType

	internal typealias OutboundIn = PacketType
	internal typealias OutboundOut = PacketType
	
	private let logger:Logger
	internal let privateKey:PrivateKey
    
    // Storing public keys for validating responses after we send initiation
    internal var peers:[PeerIndex:PublicKey] = [:]
	
	// Temp var for testing
	internal var underLoad:Bool = true
    
	// When will the cookies be ready?
	internal let ovenTimer:TimeAmount = .seconds(120)
	
	internal var secretCookieR:Result8 = try! generateSecureRandomBytes(as:Result8.self)
	
    // Timers for checking incoming initation packets
    internal var initiationTimers:[PeerIndex:TAI64N] = [:]

	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result32, h:Result32)] = [:]
	
	internal init(privateKey:consuming PrivateKey, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		self.logger = buildLogger
		self.privateKey = privateKey
	}
	
	private func generateNewCookieR(context: ChannelHandlerContext) {
		context.eventLoop.scheduleRepeatedTask(initialDelay: ovenTimer, delay: ovenTimer) { [weak self] _ in
			guard let self = self else { return }
			self.secretCookieR = try! generateSecureRandomBytes(as:Result8.self)
		}
	}

	internal borrowing func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif

		// handles handshake packets, else passes them down
		do {
			try withUnsafePointer(to:privateKey) { responderPrivateKey in
				switch unwrapInboundIn(data) {
                    // Validate initiation packet and send response upon successfull validation
					case .handshakeInitiation(let endpoint, let payload):
						logger.debug("received handshake initiation packet", metadata:["remote_address":"\(endpoint.description)"])
						var val = try HandshakeInitiationMessage.validateInitiationMessage([payload], responderStaticPrivateKey: responderPrivateKey)
						peers[payload.payload.initiatorPeerIndex] = val.initPublicKey
						
						// Check handshake packet time
						if let initiationTime = initiationTimers[payload.payload.initiatorPeerIndex] {
							if(val.timestamp <= initiationTime) {
								return
							}
						}
						initiationTimers[payload.payload.initiatorPeerIndex] = val.timestamp
						
						// Check if we are under heavy load
						if underLoad {
							// Create and send cookie
							let publicKey = withUnsafePointer(to: privateKey) { privateKey in
								return PublicKey(privateKey: privateKey)
							}
							let cookie = try CookieReplyMessage.forgeCookieReply(receiverPeerIndex: payload.payload.initiatorPeerIndex, myStaticPublicKey: publicKey, R: secretCookieR, A: endpoint, M: payload.msgMac1)
							let packet: PacketType = .cookie(endpoint, cookie)
							context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess {
								print("Cookie reply message sent to \(endpoint)")
							}
						}
						let sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed())
						let response = try HandshakeResponseMessage.forgeResponseState(c:val.c, h:val.h, initiatorPeerIndex: payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey)
						let authResponse = try HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &val.initPublicKey, payload:response.payload)
						let packet: PacketType = .handshakeResponse(endpoint, authResponse)
						
						context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess {
							print("Handshake response sent to \(endpoint)")
						}
                        
                        // Pass data for creating transit keys
                        let keyPacket: PacketType = .keyExchange(val.initPublicKey, endpoint, response.payload.responderIndex, response.c, false)
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
                                
                                // Pass data for creating transit keys
								let packet: PacketType = .keyExchange(peers[payload.payload.responderIndex]!, endpoint, payload.payload.responderIndex, val.c, true)
                                logger.debug("Sending key exhange packet to data handler")
                                context.fireChannelRead(wrapInboundOut(packet))
							}
						}
						
					case .cookie(let endpoint, let payload):
						logger.debug("received cookie packet", metadata:["remote_address":"\(endpoint.description)"])
						
						guard let peerPublicKey = peers[payload.receiverIndex] else { return }
						try withUnsafePointer(to:privateKey) { privateKey in
							try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
								let (c, h, ephiPrivateKey, payload) = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
								initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
								initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
								logger.debug("successfully forged handshake initiation message", metadata:["peer_endpoint":"\(endpoint.description)", "peer_public_key":"\(peerPublicKey.debugDescription)"])
								context.writeAndFlush(wrapOutboundOut(PacketType.handshakeInitiation(endpoint, try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload:payload))), promise:nil)
							}
						}
                        
                    case .encryptedTransit(let endpoint, let payload):
                        logger.debug("Data transit packet sent to data handler")
                        context.fireChannelRead(wrapInboundOut(PacketType.encryptedTransit(endpoint, payload)))
                        
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
            case let .initiationInvoker(peerPublicKey, endpoint):
                do {
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
            case .encryptedTransit(let endpoint, let payload):
                logger.debug("Sending transit packout down to packet handler")
                context.writeAndFlush(wrapOutboundOut(PacketType.encryptedTransit(endpoint, payload)), promise:promise)
            default:
                return
        }
	}
}

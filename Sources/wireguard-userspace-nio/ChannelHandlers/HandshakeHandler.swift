import NIO
import RAW_dh25519
import RAW_xchachapoly
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
	internal var peersAddressBook:[SocketAddress:PublicKey] = [:]
	
	// Storing initiation packets unless they recieve a validation
	internal var initiationPackets:[PeerIndex:HandshakeInitiationMessage.AuthenticatedPayload] = [:]
	
	// Precomputed key for the cookie
	internal var precomputedCookieKey:RAW_xchachapoly.Key
	
	// Temp var for testing cookies
	internal var underLoad:Bool = true
    
	// When will the cookies be ready? For the secretCookieR
	internal let ovenTimer:TimeAmount = .seconds(120)
	internal var secretCookieR:Result8 = try! generateSecureRandomBytes(as:Result8.self)
	
	// Rekey variables
	private var rekeyAttemptTasks: [PeerIndex: RepeatedTask] = [:]
	private var rekeyAttemptsStartTime: [PeerIndex: NIODeadline] = [:]
	
	// Rekey timers
	private let rekeyTimeout: TimeAmount = .seconds(5)
	private let rekeyAttemptTime: TimeAmount = .seconds(90)
	
    // Timers for checking incoming initation packets
    internal var initiationTimers:[PeerIndex:TAI64N] = [:]

	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result32, h:Result32)] = [:]
	
	internal init(privateKey:consuming PrivateKey, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		self.logger = buildLogger
		self.privateKey = privateKey
		
		// Pre-computing HASH(LABEL-COOKIE || Spub)
		let publicKey = withUnsafePointer(to: self.privateKey) { privateKey in
			return PublicKey(privateKey: privateKey)
		}
		var hasher = try! WGHasherV2<RAW_xchachapoly.Key>()
		try! hasher.update([UInt8]("cookie--".utf8))
		try! hasher.update(publicKey)
		precomputedCookieKey = try! hasher.finish()
	}
	
	private func generateNewCookieR(context: ChannelHandlerContext) {
		context.eventLoop.scheduleRepeatedTask(initialDelay: ovenTimer, delay: ovenTimer) { [weak self] _ in
			guard let self = self else { return }
			self.secretCookieR = try! generateSecureRandomBytes(as:Result8.self)
		}
	}
	
	// Sends the cookie after REKEY-TIMEOUT time
	private func sendCookieInitiation(context: ChannelHandlerContext, cookie:PacketType) {
		context.eventLoop.scheduleTask(in: .seconds(5)) { [weak self] in
			guard let self = self else { return }
			context.writeAndFlush(wrapOutboundOut(cookie), promise:nil)
		}
	}
	
	// Rekey attempt when initiation doesn't get a valid response
	private func startRekeyAttempts(for peerIndex: PeerIndex, context: ChannelHandlerContext, peerPublicKey: PublicKey, endpoint: SocketAddress) {
		guard rekeyAttemptTasks[peerIndex] == nil else { return }

		rekeyAttemptsStartTime[peerIndex] = .now()

		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: rekeyTimeout, delay: rekeyTimeout) { [weak self] _ in
			guard let self = self else { return }

			let now = NIODeadline.now()
			guard let start = self.rekeyAttemptsStartTime[peerIndex],
				  now - start < self.rekeyAttemptTime else {
				self.rekeyAttemptTasks[peerIndex]?.cancel()
				self.rekeyAttemptTasks[peerIndex] = nil
				self.logger.debug("Rekey attempt time expired for peer \(peerIndex)")
				return
			}

			self.logger.debug("Retrying handshake for peer \(peerIndex) due to timeout")
			context.writeAndFlush(self.wrapOutboundOut(.handshakeInitiation(endpoint, <#T##HandshakeInitiationMessage.AuthenticatedPayload#>)), promise: nil)
		}
		
		rekeyAttemptTasks[peerIndex] = task
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

						// Check if we are under heavy load
						if underLoad {
							
							let (mac1Valid, mac2Valid) = try HandshakeInitiationMessage.validateUnderLoad([payload], responderStaticPrivateKey: responderPrivateKey, R: secretCookieR, A: endpoint)
							
							if(!mac1Valid) { return }
							else if(!mac2Valid) {
								// Create and send cookie
								let cookie = try CookieReplyMessage.forgeCookieReply(receiverPeerIndex: payload.payload.initiatorPeerIndex, k: precomputedCookieKey, R: secretCookieR, A: endpoint, M: payload.msgMac1)
								let packet: PacketType = .cookie(endpoint, cookie)
								context.writeAndFlush(self.wrapOutboundOut(packet)).whenSuccess {
									print("Cookie reply message sent to \(endpoint)")
								}
								return
							}
						}
						
						var val = try HandshakeInitiationMessage.validateInitiationMessage([payload], responderStaticPrivateKey: responderPrivateKey)
						peers[payload.payload.initiatorPeerIndex] = val.initPublicKey
						
						// Check handshake packet time
						if let initiationTime = initiationTimers[payload.payload.initiatorPeerIndex] {
							if(val.timestamp <= initiationTime) {
								return
							}
						}
						initiationTimers[payload.payload.initiatorPeerIndex] = val.timestamp
						
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
						guard let peerPublicKey = peersAddressBook[endpoint] else {
							logger.error("Peer endpoint doesn't exist at \(endpoint)")
							return
						}
						try withUnsafePointer(to:privateKey) { myPrivateKeyPointer in
							try withUnsafePointer(to:initiatorEphiPrivateKey) { initiatorEphiPrivateKeyPtr in
								// Validate handshake response
								let val = try HandshakeResponseMessage.validateResponseMessage(c:existingC, h:existingH, message:&payload, initiatorStaticPrivateKey:myPrivateKeyPointer, initiatorEphemeralPrivateKey:initiatorEphiPrivateKeyPtr, preSharedKey:Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed()))
								logger.info("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.initiatorIndex)"])
								
								// Remove held initiation packet
								initiationPackets[payload.payload.initiatorIndex] = nil
                                
                                // Pass data for creating transit keys
								let packet: PacketType = .keyExchange(peerPublicKey, endpoint, payload.payload.responderIndex, val.c, true)
                                logger.debug("Sending key exhange packet to data handler")
                                context.fireChannelRead(wrapInboundOut(packet))
								
								// Stop rekey since handshake completed
								rekeyAttemptTasks[payload.payload.initiatorIndex]?.cancel()
								rekeyAttemptTasks[payload.payload.initiatorIndex] = nil
								rekeyAttemptsStartTime[payload.payload.initiatorIndex] = nil
							}
						}
						
					// Received cookie, recreate initiation handshake message with mac2
					case .cookie(let endpoint, let cookiePayload):
						logger.debug("received cookie packet", metadata:["remote_address":"\(endpoint.description)"])
						
						guard let peerPublicKey = peersAddressBook[endpoint] else {
							logger.error("No peer public key for \(endpoint)")
							return
						}
						guard let initiationPacket = initiationPackets[cookiePayload.receiverIndex] else {
							logger.error("No retained initiation packet")
							return
						}
						withUnsafePointer(to:privateKey) { privateKey in
							withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
								var phantomCookie: PacketType
								do {
									let authCookiePacket = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload:initiationPacket.payload, cookie: cookiePayload)
									initiationPackets[initiationPacket.payload.initiatorPeerIndex] = authCookiePacket
									phantomCookie = PacketType.handshakeInitiation(endpoint, authCookiePacket)
								} catch {
									logger.debug("Failed to validate cookie and create msgMac2")
									return
								}
								logger.debug("Cookie sent to shipping container... (packet handler)")
								sendCookieInitiation(context: context, cookie: phantomCookie)
								
								rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex]?.cancel()
								rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex] = nil
								rekeyAttemptsStartTime[initiationPacket.payload.initiatorPeerIndex] = nil
								
								startRekeyAttempts(for: initiationPacket.payload.initiatorPeerIndex, context: context, peerPublicKey: peerPublicKey, endpoint: endpoint)
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
					peersAddressBook[endpoint] = peerPublicKey
                    try withUnsafePointer(to:privateKey) { privateKey in
                        try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
							// Forge initiation packet
                            let (c, h, ephiPrivateKey, payload) = try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
							
							// Store keys and c/h for response
                            initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
                            initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
							
							// Send initiation packet to packet handler
                            logger.debug("successfully forged handshake initiation message", metadata:["peer_endpoint":"\(endpoint.description)", "peer_public_key":"\(peerPublicKey.debugDescription)"])
							let authPayload = try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: expectedPeerPublicKey, payload:payload)
                            context.writeAndFlush(wrapOutboundOut(PacketType.handshakeInitiation(endpoint, authPayload)), promise:promise)
							
							// Store packet for potential cookie
							initiationPackets[payload.initiatorPeerIndex] = authPayload
							
							// Start rekey timer
							startRekeyAttempts(for: payload.initiatorPeerIndex, context: context, peerPublicKey: peerPublicKey, endpoint: endpoint)
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

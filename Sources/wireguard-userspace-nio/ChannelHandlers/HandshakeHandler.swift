import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core

// handles the handshakes for the WireGuard protocol.
// - NOTE: this handler is marked as `@unchecked Sendable` because it trusts NIO event loops to manage its internal state correctly
internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (Endpoint, Message)
	internal typealias InboundOut = PacketTypeInbound
	internal typealias OutboundIn = PacketTypeOutbound
	internal typealias OutboundOut = (Endpoint, Message)
	
	private enum HandshakeGeometry<HandshakeSessionType>:Hashable, Equatable where HandshakeSessionType:Hashable, HandshakeSessionType:Equatable {
		case selfInitiated(m:HandshakeSessionType, mp:HandshakeSessionType)
		case peerInitiated(m:HandshakeSessionType, mp:HandshakeSessionType)
		var peerIndex:HandshakeSessionType {
			switch self {
				case .selfInitiated(m:let m, mp:let mp):
				return m
				case .peerInitiated(m:let m, mp:let mp):
				return mp
			}
		}
		var selfIndex:HandshakeSessionType {
			switch self {
				case .selfInitiated(m:let m, mp:let mp):
				return m
				case .peerInitiated(m:let m, mp:let mp):
				return mp
			}
		}
	}

	private var log:Logger
	internal let privateKey:MemoryGuarded<PrivateKey>
	
	// Storing public keys for validating responses after we send initiation
	internal var peers:[PeerIndex:PublicKey] = [:]
	internal var peerEndpoints:[PeerIndex:Endpoint] = [:]
	internal var pubEndpoints:[PublicKey:Endpoint] = [:]
	// m peers
	internal var peerMPublicKey:[PeerIndex:PublicKey] = [:]
	internal var peerMEndpoint:[PeerIndex:Endpoint] = [:]
	
	// stores a mapping of an initiatiors peer index and the corresponding authenticated payload that was generated
	internal var initiatorPackets:[PeerIndex:Message.Initiation.Payload.Authenticated] = [:]

	internal var peersAddressBook:[Endpoint:PublicKey] = [:]
	
	// Precomputed key for the cookie
	internal let precomputedCookieKey:RAW_xchachapoly.Key
	
	// Temp var for testing cookies
	internal var underLoad:Bool = false
	
	// When will the cookies be ready? For the secretCookieR
	internal let ovenTimer:TimeAmount = .seconds(120)
	internal var secretCookieR:Result.Bytes8 = try! generateSecureRandomBytes(as:Result.Bytes8.self)
	
	// Rekey variables
	private var rekeyAttemptTasks: [PeerIndex: RepeatedTask] = [:]
	private var rekeyAttemptsStartTime: [PeerIndex: NIODeadline] = [:]
	private var isRekeying: [PublicKey: Bool] = [:]
	
	// Rekey timers
	private let rekeyTimeout: TimeAmount = .seconds(5)
	private let rekeyAttemptTime: TimeAmount = .seconds(90)

	// Timers for checking incoming initation packets
	internal var initiationTimers:[PeerIndex:TAI64N] = [:]
	private var initiatorEphemeralPrivateKey:[PeerIndex:MemoryGuarded<PrivateKey>] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result.Bytes32, h:Result.Bytes32)] = [:]
	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
		privateKey = pkIn
		// pre-computing HASH(LABEL-COOKIE || Spub)
		var hasher = try! WGHasher<RAW_xchachapoly.Key>()
		try! hasher.update([UInt8]("cookie--".utf8))
		try! hasher.update(PublicKey(privateKey: privateKey))
		precomputedCookieKey = try! hasher.finish()
	}
	internal func handlerAdded(context:ChannelHandlerContext) {
		var logger = log
		logger.trace("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		var logger = log
		logger.trace("handler removed from NIO pipeline.")
	}

	// Sends the cookie after REKEY-TIMEOUT time
	private func sendCookieInitiation(context:ChannelHandlerContext, endpoint:Endpoint, cookie:Message) {
		context.eventLoop.scheduleTask(in:.seconds(5)) { [c = ContextContainer(context:context)] in
			c.accessContext { contextPointer in
				contextPointer.pointee.writeAndFlush(self.wrapOutboundOut((endpoint, cookie)), promise:nil)
			}
		}
	}
	
	// Rekey attempt when initiation doesn't get a valid response
	private func startRekeyAttempts(for peerIndex:PeerIndex, context:ChannelHandlerContext, peerPublicKey:PublicKey, endpoint:Endpoint) {
		var logger = log
		guard rekeyAttemptTasks[peerIndex] == nil else { return }
		rekeyAttemptsStartTime[peerIndex] = .now()
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: rekeyTimeout, delay: rekeyTimeout) { [weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			let now = NIODeadline.now()
			guard let start = rekeyAttemptsStartTime[peerIndex],
				now - start < rekeyAttemptTime else {
				rekeyAttemptTasks[peerIndex]?.cancel()
				rekeyAttemptTasks[peerIndex] = nil
				logger.debug("rekey attempt time expired for peer \(peerIndex)")
				return
			}

			logger.debug("Retrying handshake for peer \(peerIndex) due to timeout")
			c.accessContext { contextPointer in
				contextPointer.pointee.writeAndFlush(wrapOutboundOut((endpoint, .initiation(initiatorPackets[peerIndex]!))), promise: nil)
			}
		}
		rekeyAttemptTasks[peerIndex] = task
	}


	internal borrowing func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		// handles handshake packets, else passes them down
		do {
			let (endpoint, payload) = unwrapInboundIn(data)
			logger[metadataKey:"peer_endpoint"] = "\(endpoint)"
			switch payload {
				// Validate initiation packet and send response upon successfull validation
				case .initiation(let payload):
					/*
					peers role: initiator
					our role: responder
					=================
					Im = responder peer index
					Im' = initiator peer index
					*/
					if underLoad == true {
						do {
							try payload.validateUnderLoadNoNIO(responderStaticPrivateKey:privateKey, R: secretCookieR, endpoint:endpoint)
						} catch Message.Initiation.Payload.Authenticated.Error.mac1Invalid {
							// Ignore the packet, it is invalid
							logger.debug("received invalid handshake initiation packet, ignoring")
							return
						} catch let error {
							// Create and send cookie
							let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
							context.writeAndFlush(wrapOutboundOut((endpoint, .cookie(cookie)))).whenSuccess { [logger = logger, e = endpoint] in
								logger.trace("cookie reply message sent to endpoint")
							}
							return
						}
					}
					let responderPeerIndex = try! generateSecureRandomBytes(as:PeerIndex.self)
					var (c, h, initiatorStaticPublicKey, timestamp) = try payload.validate(responderStaticPrivateKey: privateKey)
					logger.debug("successfully validated handshake initiation packet", metadata:["peer_index_initiator":"\(payload.payload.initiatorPeerIndex)", "peer_index_responder":"\(responderPeerIndex)", "peer_public_key":"\(initiatorStaticPublicKey)"])

					// check handshake packet time
					if let initiationTime = initiationTimers[payload.payload.initiatorPeerIndex] {
						if (timestamp <= initiationTime) {
							return
						}
					}
					initiationTimers[payload.payload.initiatorPeerIndex] = timestamp
					let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
					let response = try Message.Response.Payload.forge(c:c, h:h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &initiatorStaticPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey, responderPeerIndex:responderPeerIndex)
					let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&initiatorStaticPublicKey)
					
					// store mp values					
					
					peers[authResponse.payload.responderIndex] = initiatorStaticPublicKey
					peerEndpoints[authResponse.payload.responderIndex] = endpoint
					pubEndpoints[initiatorStaticPublicKey] = endpoint
										
					initiatorPackets.removeValue(forKey:payload.payload.initiatorPeerIndex) 
					
					peerMPublicKey[payload.payload.initiatorPeerIndex] = initiatorStaticPublicKey
					peerMEndpoint[payload.payload.initiatorPeerIndex] = endpoint
					
					context.writeAndFlush(wrapOutboundOut((endpoint, .response(authResponse)))).whenSuccess { [logger = logger] in
						logger.trace("handshake response sent successfully")
					}

					let keyPacket:PacketTypeInbound = .keyExchange(initiatorStaticPublicKey, response.payload.responderIndex, response.c, false)
					context.fireChannelRead(wrapInboundOut(keyPacket))
					
				case .response(let payload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
					guard let initiatorEphiPrivateKey = initiatorEphemeralPrivateKey[payload.payload.initiatorIndex] else {
						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					guard let (existingC, existingH) = initiatorChainingData[payload.payload.initiatorIndex] else {
						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing chaining data")
						return
					}
					let val = try payload.validate(c:existingC, h:existingH, initiatorStaticPrivateKey:privateKey, initiatorEphemeralPrivateKey:initiatorEphiPrivateKey, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
					
					logger.debug("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.responderIndex)"])
					
					guard let peerPublicKey = peerMPublicKey[payload.payload.initiatorIndex] else {
						logger.error("peer public key could not be correlated from the initiator peer index")
						return
					}
					
					peers[payload.payload.responderIndex] = peerPublicKey
					peerEndpoints[payload.payload.responderIndex] = endpoint
					pubEndpoints[peerPublicKey] = endpoint
										
					peerMPublicKey[payload.payload.initiatorIndex] = peerPublicKey
					peerMEndpoint[payload.payload.initiatorIndex] = endpoint

					guard initiatorPackets.removeValue(forKey:payload.payload.initiatorIndex) != nil else {
						logger.critical("inconsistent peer endpoint data found within handler. this is an internal error")
						return
					}
					
					// Pass data for creating transit keys
					let packet:PacketTypeInbound = .keyExchange(peerPublicKey, payload.payload.responderIndex, val.c, true)
					context.fireChannelRead(wrapInboundOut(packet))
					
					// Stop rekey since handshake completed
					rekeyAttemptTasks[payload.payload.initiatorIndex]?.cancel()
					rekeyAttemptTasks[payload.payload.initiatorIndex] = nil
					rekeyAttemptsStartTime[payload.payload.initiatorIndex] = nil
					isRekeying[peerPublicKey] = nil
					
				// Received cookie, recreate initiation handshake message with mac2
				case .cookie(let cookiePayload):
					logger.debug("received cookie packet", metadata:["peer_endpoint":"\(endpoint)"])
					guard let peerPublicKey = peersAddressBook[endpoint] else {
						logger.error("no peer public key for \(endpoint)")
						return
					}
					guard let initiationPacket = initiatorPackets[cookiePayload.receiverIndex] else {
						logger.error("no retained initiation packet")
						return
					}
					withUnsafePointer(to:privateKey) { privateKey in
						withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
							var phantomCookie:Message.Initiation.Payload.Authenticated
							do {
								phantomCookie = try initiationPacket.payload.finalize(responderStaticPublicKey: expectedPeerPublicKey, cookie: cookiePayload)
								initiatorPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
							} catch {
								logger.error("failed to validate cookie and create msgMac2")
								return
							}
							logger.debug("cookie sent to shipping container... (packet handler)")
							sendCookieInitiation(context:context, endpoint:endpoint, cookie:.initiation(phantomCookie))
							rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex]?.cancel()
							rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex] = nil
							rekeyAttemptsStartTime[initiationPacket.payload.initiatorPeerIndex] = nil
							startRekeyAttempts(for: initiationPacket.payload.initiatorPeerIndex, context: context, peerPublicKey: peerPublicKey, endpoint: endpoint)
						}
					}

				case .data(let payload):
					guard let pk = peers[payload.header.receiverIndex] else {
						logger.critical("no peer public key for \(payload.payload.receiverIndex)")
						return
					}
					logger.trace("received data", metadata:["peer_index":"\(payload.header.receiverIndex)"])
					context.fireChannelRead(wrapInboundOut(PacketTypeInbound.encryptedTransit(pk, payload.header.receiverIndex, payload)))
			}
		} catch let error {
			logger.error("error processing handshake packet: \(error)")
			context.fireErrorCaught(error)
		}
	}
	
	internal borrowing func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		let invoke = unwrapOutboundIn(data)
		switch invoke {
			case let .handshakeInitiate(peerPublicKey, endpoint):
				/*
				peers role: responder
				our role: initiator
				=================
				Im = initiator peer index
				Im' = responder peer index (not yet known, only initiator peer index is available)
				*/
				guard isRekeying[peerPublicKey] == nil else {
					return
				}
				do {
					try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
						// Forge initiation packet
						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:privateKey, responderStaticPublicKey:expectedPeerPublicKey)
						peers[payload.initiatorPeerIndex] = peerPublicKey
						peerMPublicKey[payload.initiatorPeerIndex] = peerPublicKey
						if endpoint != nil {
							peersAddressBook[endpoint!] = peerPublicKey
							peerEndpoints[payload.initiatorPeerIndex] = endpoint!
							peerMEndpoint[payload.initiatorPeerIndex] = endpoint!
							pubEndpoints[peerPublicKey] = endpoint!
						}
						guard peerMEndpoint[payload.initiatorPeerIndex] != nil else {
							logger.critical("no peer endpoint for \(payload.initiatorPeerIndex)")
							return
						}

						// Store keys and c/h for response
						initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
						initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
						
						// Send initiation packet to packet handler
						logger.debug("successfully forged handshake initiation message", metadata:["endpoint_remote":"\(peerEndpoints[payload.initiatorPeerIndex]!)", "public-key_remote":"\(peerPublicKey)", "index_initiator":"\(payload.initiatorPeerIndex)"])
						
						let authPayload = try payload.finalize(responderStaticPublicKey:expectedPeerPublicKey)
						context.writeAndFlush(wrapOutboundOut((peerEndpoints[payload.initiatorPeerIndex]!, .initiation(authPayload))), promise:promise)

						// Store packet for potential cookie
						initiatorPackets[payload.initiatorPeerIndex] = authPayload
						
						// Start rekey timer
						startRekeyAttempts(for:payload.initiatorPeerIndex, context:context, peerPublicKey:peerPublicKey, endpoint:peerEndpoints[payload.initiatorPeerIndex]!)
						isRekeying[peerPublicKey] = true
					}
				} catch let error {
					context.fireErrorCaught(error)
					promise?.fail(error)
				}
			case .encryptedTransit(let publicKey, let payload):
				guard let ep = peerEndpoints[payload.header.receiverIndex] else {
					logger.critical("no peer endpoint for \(payload.header.receiverIndex)")
					return
				}
				guard peers[payload.header.receiverIndex] == publicKey else {
					logger.critical("peer public key mismatch")
					return
				}
				context.writeAndFlush(wrapOutboundOut((ep, .data(payload))), promise:promise)
			default:
				return
		}
	}
}

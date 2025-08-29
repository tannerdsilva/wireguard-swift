//import NIO
//import RAW_dh25519
//import RAW_xchachapoly
//import Logging
//import RAW
//import wireguard_crypto_core
//import Synchronization
//
//// handles the handshakes for the WireGuard protocol.
//// - NOTE: this handler is marked as `@unchecked Sendable` because it trusts NIO event loops to manage its internal state correctly
//internal final class HandshakeHandler:ChannelDuplexHandler, @unchecked Sendable {
//	internal typealias InboundIn = (Endpoint, Message)
//	internal typealias InboundOut = PacketTypeInbound
//	internal typealias OutboundIn = PacketTypeOutbound
//	internal typealias OutboundOut = (Endpoint, Message)
//	
//	/// logger that will be used to produce output for the work completed by this handler
//	private let log:Logger
//	internal let privateKey:MemoryGuarded<PrivateKey>
//	
//	// Storing public keys for validating responses after we send initiation
//	internal var peers:[PeerIndex:PublicKey] = [:]
//
//	internal var peerMPublicKey:[PeerIndex:PublicKey] = [:]
//	internal var myPeerIndicies:Set<PeerIndex> = []
//	internal var pubEndpoints:[PublicKey:Endpoint] = [:]
//	private var peerGeometry:[PublicKey:HandshakeGeometry<PeerIndex>] = [:]
//	
//	// stores a mapping of an initiatiors peer index and the corresponding authenticated payload that was generated
//	
//	// Temp var for testing cookies
//	internal var underLoad:Bool = false
//	internal let congestionModeEnable:Atomic<Bool> = .init(false)
//	
//	// When will the cookies be ready? For the secretCookieR
//	internal let ovenTimer:TimeAmount = TimeAmount.seconds(120)
//	internal var secretCookieR:Result.Bytes8 = try! generateSecureRandomBytes(as:Result.Bytes8.self)
//
//	internal let precomputedCookieKey:RAW_xchachapoly.Key
//
//	// Rekey timers
//	private let rekeyTimeout = TimeAmount.seconds(5)
//	private let rekeyAttemptTime = TimeAmount.seconds(90)
//	
//	private var rekeyInfo = Rekey()
//	private var selfInitiatedInfo = SelfInitiated()
//
//	private struct Rekey {
//		internal var rekeyAttemptTasks:[PeerIndex:RepeatedTask] = [:]
//		internal var rekeyAttemptsStartTime:[PeerIndex:NIODeadline] = [:]
//		internal var isRekeying:[PublicKey:Bool] = [:]
//	}
//	private struct SelfInitiated {
//		internal var initiationTimers:[PublicKey:TAI64N] = [:]
//		internal var initiatorEphemeralPrivateKey:[PeerIndex:MemoryGuarded<PrivateKey>] = [:]
//		internal var initiatorChainingData:[PeerIndex:(c:Result.Bytes32, h:Result.Bytes32)] = [:]
//		internal var initiatorPackets:[PeerIndex:Message.Initiation.Payload.Authenticated] = [:]
//	}
//	
//	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, logLevel:Logger.Level) {
//		privateKey = pkIn
//		let publicKey = PublicKey(privateKey: privateKey)
//		var buildLogger = Logger(label:"\(String(describing:Self.self))")
//		buildLogger.logLevel = logLevel
//		buildLogger[metadataKey:"public-key_self"] = "\(publicKey)"
//		log = buildLogger
//		// pre-computing HASH(LABEL-COOKIE || Spub)
//		var hasher = try! WGHasher<RAW_xchachapoly.Key>()
//		try! hasher.update([UInt8]("cookie--".utf8))
//		try! hasher.update(publicKey)
//		precomputedCookieKey = try! hasher.finish()
//	}
//	internal func handlerAdded(context:ChannelHandlerContext) {
//		var logger = log
//		logger.debug("handler added to NIO pipeline.")
//	}
//	
//	internal func handlerRemoved(context:ChannelHandlerContext) {
//		var logger = log
//		logger.debug("handler removed from NIO pipeline.")
//	}
//
//	// Sends the cookie after REKEY-TIMEOUT time
//	private func sendCookieInitiation(context:ChannelHandlerContext, endpoint:Endpoint, cookie:Message) {
//		context.eventLoop.scheduleTask(in:.seconds(5)) { [c = ContextContainer(context:context)] in
//			c.accessContext { contextPointer in
//				contextPointer.pointee.writeAndFlush(self.wrapOutboundOut((endpoint, cookie)), promise:nil)
//			}
//		}
//	}
//	
//	// Rekey attempt when initiation doesn't get a valid response
//	private func startRekeyAttempts(for peerIndex:PeerIndex, context:ChannelHandlerContext, peerPublicKey:PublicKey, endpoint:Endpoint) {
//		var logger = log
//		guard rekeyInfo.rekeyAttemptTasks[peerIndex] == nil else { return }
//		rekeyInfo.rekeyAttemptsStartTime[peerIndex] = .now()
//		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: rekeyTimeout, delay: rekeyTimeout) { [weak self, c = ContextContainer(context:context)] _ in
//			guard let self = self else { return }
//			let now = NIODeadline.now()
//			guard let start = rekeyInfo.rekeyAttemptsStartTime[peerIndex],
//				now - start < rekeyAttemptTime else {
//				rekeyInfo.rekeyAttemptTasks[peerIndex]?.cancel()
//				rekeyInfo.rekeyAttemptTasks[peerIndex] = nil
//				logger.debug("rekey attempt time expired for peer \(peerIndex)")
//				return
//			}
//
//			logger.debug("Retrying handshake for peer \(peerIndex) due to timeout")
//			c.accessContext { contextPointer in
//				contextPointer.pointee.writeAndFlush(wrapOutboundOut((endpoint, .initiation(selfInitiatedInfo.initiatorPackets[peerIndex]!))), promise: nil)
//			}
//		}
//		rekeyInfo.rekeyAttemptTasks[peerIndex] = task
//	}
//
//	internal borrowing func channelRead(context:ChannelHandlerContext, data:NIOAny) {
//		#if DEBUG
//		context.eventLoop.assertInEventLoop()
//		#endif
//		var logger = log
//		// handles handshake packets, else passes them down
//		do {
//			let (endpoint, payload) = unwrapInboundIn(data)
//			logger[metadataKey:"endpoint_remote"] = "\(endpoint)"
//			switch payload {
//				// Validate initiation packet and send response upon successfull validation
//				case .initiation(let payload):
//					/*
//					peers role: initiator
//					our role: responder
//					=================
//					Im = responder peer index
//					Im' = initiator peer index
//					*/
//					if underLoad == true {
//						do {
//							try payload.validateUnderLoadNoNIO(responderStaticPrivateKey:privateKey, R: secretCookieR, endpoint:endpoint)
//						} catch Message.Initiation.Payload.Authenticated.Error.mac1Invalid {
//							// Ignore the packet, it is invalid
//							logger.debug("received invalid handshake initiation packet, ignoring")
//							return
//						} catch let error {
//							// Create and send cookie
//							let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
//							context.writeAndFlush(wrapOutboundOut((endpoint, .cookie(cookie)))).whenSuccess { [logger = logger, e = endpoint] in
//								logger.trace("cookie reply message sent to endpoint")
//							}
//							return
//						}
//					}
//					let responderPeerIndex = try! generateSecureRandomBytes(as:PeerIndex.self)
//					var (c, h, initiatorStaticPublicKey, timestamp) = try payload.validate(responderStaticPrivateKey: privateKey)
//					logger.debug("successfully validated handshake initiation packet", metadata:["index_initiator":"\(payload.payload.initiatorPeerIndex)", "index_responder":"\(responderPeerIndex)", "public-key_remote":"\(initiatorStaticPublicKey)"])
//					
//					let geometry = HandshakeGeometry<PeerIndex>.peerInitiated(m:responderPeerIndex, mp:payload.payload.initiatorPeerIndex)
//					peerGeometry[initiatorStaticPublicKey] = geometry
//					myPeerIndicies.update(with:responderPeerIndex)
//					
//					// check handshake packet time
//					if let initiationTime = selfInitiatedInfo.initiationTimers[initiatorStaticPublicKey] {
//						if (timestamp <= initiationTime) {
//							return
//						}
//					}
//					selfInitiatedInfo.initiationTimers[initiatorStaticPublicKey] = timestamp
//					let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
//					let response = try Message.Response.Payload.forge(c:c, h:h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &initiatorStaticPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey, responderPeerIndex:responderPeerIndex)
//					let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&initiatorStaticPublicKey)
//					
//					// store mp values
//					
//					peers[authResponse.payload.responderIndex] = initiatorStaticPublicKey
//					pubEndpoints[initiatorStaticPublicKey] = endpoint
//										
//					selfInitiatedInfo.initiatorPackets.removeValue(forKey:payload.payload.initiatorPeerIndex) 
//										
//					context.writeAndFlush(wrapOutboundOut((endpoint, .response(authResponse)))).whenSuccess { [logger = logger] in
//						logger.trace("handshake response sent successfully")
//					}
//
//					let keyPacket = PacketTypeInbound.keyExchange(initiatorStaticPublicKey, response.payload.responderIndex, response.c, false, geometry)
//					context.fireChannelRead(wrapInboundOut(keyPacket))
//					
//				case .response(let payload):
//					/*
//					peers role: responder
//					our role: initiator
//					=================
//					Im = initiator peer index
//					Im' = responder peer index
//					*/
//					guard let initiatorEphiPrivateKey = selfInitiatedInfo.initiatorEphemeralPrivateKey[payload.payload.initiatorIndex] else {
//						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
//						return
//					}
//					guard let (existingC, existingH) = selfInitiatedInfo.initiatorChainingData[payload.payload.initiatorIndex] else {
//						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing chaining data")
//						return
//					}
//					let val = try payload.validate(c:existingC, h:existingH, initiatorStaticPrivateKey:privateKey, initiatorEphemeralPrivateKey:initiatorEphiPrivateKey, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
//					
//					logger.debug("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.responderIndex)"])
//					
//					guard let peerPublicKey = peerMPublicKey[payload.payload.initiatorIndex] else {
//						logger.error("peer public key could not be correlated from the initiator peer index")
//						return
//					}
//					
//					peers[payload.payload.responderIndex] = peerPublicKey
//					pubEndpoints[peerPublicKey] = endpoint
//					
//					let geometry = HandshakeGeometry<PeerIndex>.selfInitiated(m:payload.payload.initiatorIndex, mp:payload.payload.responderIndex)
//					peerGeometry[peerPublicKey] = geometry
//					myPeerIndicies.update(with:payload.payload.initiatorIndex)
//
//					guard selfInitiatedInfo.initiatorPackets.removeValue(forKey:payload.payload.initiatorIndex) != nil else {
//						logger.critical("inconsistent peer endpoint data found within handler. this is an internal error")
//						return
//					}
//					
//					// Pass data for creating transit keys
//					let packet = PacketTypeInbound.keyExchange(peerPublicKey, payload.payload.responderIndex, val.c, true, geometry)
//					context.fireChannelRead(wrapInboundOut(packet))
//					
//					// Stop rekey since handshake completed
//					rekeyInfo.rekeyAttemptTasks[payload.payload.initiatorIndex]?.cancel()
//					rekeyInfo.rekeyAttemptTasks[payload.payload.initiatorIndex] = nil
//					rekeyInfo.rekeyAttemptsStartTime[payload.payload.initiatorIndex] = nil
//					rekeyInfo.isRekeying[peerPublicKey] = nil
//					
//				// Received cookie, recreate initiation handshake message with mac2
//				case .cookie(let cookiePayload):
//					/*
//					peers role: responder
//					our role: initiator
//					=================
//					Im = initiator peer index
//					Im' = responder peer index
//					*/
//					guard let peerPublicKey = peerMPublicKey[cookiePayload.receiverIndex] else {
//						logger.critical("peer public key could not be correlated from the initiator peer index")
//						return
//					}
//					guard let initiationPacket = selfInitiatedInfo.initiatorPackets.removeValue(forKey:cookiePayload.receiverIndex) else {
//						logger.critical("initiator peer index could not be correlated with any forged initiation packets.")
//						return
//					}
//					logger.debug("received cookie packet", metadata:["endpoint_remote":"\(endpoint)", "public-key_remote":"\(peerPublicKey)"])
//					withUnsafePointer(to:privateKey) { privateKey in
//						withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
//							var phantomCookie:Message.Initiation.Payload.Authenticated
//							do {
//								phantomCookie = try initiationPacket.payload.finalize(responderStaticPublicKey: expectedPeerPublicKey, cookie: cookiePayload)
//								selfInitiatedInfo.initiatorPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
//							} catch {
//								logger.error("failed to validate cookie and create msgMac2")
//								return
//							}
//							logger.debug("cookie sent to shipping container... (packet handler)")
//							sendCookieInitiation(context:context, endpoint:endpoint, cookie:.initiation(phantomCookie))
//							rekeyInfo.rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex]?.cancel()
//							rekeyInfo.rekeyAttemptTasks[initiationPacket.payload.initiatorPeerIndex] = nil
//							rekeyInfo.rekeyAttemptsStartTime[initiationPacket.payload.initiatorPeerIndex] = nil
//							startRekeyAttempts(for: initiationPacket.payload.initiatorPeerIndex, context: context, peerPublicKey: peerPublicKey, endpoint: endpoint)
//						}
//					}
//
//				case .data(let payload):
//					guard let pk = peers[payload.header.receiverIndex] else {
//						logger.critical("no peer public key for \(payload.header.receiverIndex)")
//						return
//					}
//					logger.trace("received data", metadata:["peer_index":"\(payload.header.receiverIndex)"])
//					context.fireChannelRead(wrapInboundOut(PacketTypeInbound.encryptedTransit(pk, payload.header.receiverIndex, peerGeometry[pk]!, payload)))
//			}
//		} catch let error {
//			logger.error("error processing handshake packet: \(error)")
//			context.fireErrorCaught(error)
//		}
//	}
//	
//	internal borrowing func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
//		#if DEBUG
//		context.eventLoop.assertInEventLoop()
//		#endif
//		var logger = log
//		let invoke = unwrapOutboundIn(data)
//		switch invoke {
//			case let .handshakeInitiate(peerPublicKey, endpoint):
//				/*
//				peers role: responder
//				our role: initiator
//				=================
//				Im = initiator peer index
//				Im' = responder peer index (not yet known, only initiator peer index is available)
//				*/
//				guard rekeyInfo.isRekeying[peerPublicKey] == nil else {
//					return
//				}
//				do {
//					try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
//						// Forge initiation packet
//						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:privateKey, responderStaticPublicKey:expectedPeerPublicKey)
//						peers[payload.initiatorPeerIndex] = peerPublicKey
//						peerMPublicKey[payload.initiatorPeerIndex] = peerPublicKey
//						if endpoint != nil {
//							pubEndpoints[peerPublicKey] = endpoint!
//						}
//						guard pubEndpoints[expectedPeerPublicKey.pointee] != nil else {
//							logger.critical("no peer endpoint for \(payload.initiatorPeerIndex)")
//							return
//						}
//
//						// Store keys and c/h for response
//						selfInitiatedInfo.initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
//						selfInitiatedInfo.initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
//						
//						// send initiation packet to packet handler
//						logger.debug("successfully forged handshake initiation message", metadata:["endpoint_remote":"\(pubEndpoints[expectedPeerPublicKey.pointee]!)", "public-key_remote":"\(peerPublicKey)", "index_initiator":"\(payload.initiatorPeerIndex)"])
//						
//						let authPayload = try payload.finalize(responderStaticPublicKey:expectedPeerPublicKey)
//						context.writeAndFlush(wrapOutboundOut((pubEndpoints[expectedPeerPublicKey.pointee]!, .initiation(authPayload))), promise:promise)
//
//						// Store packet for potential cookie
//						selfInitiatedInfo.initiatorPackets[payload.initiatorPeerIndex] = authPayload
//						
//						// Start rekey timer
//						startRekeyAttempts(for:payload.initiatorPeerIndex, context:context, peerPublicKey:peerPublicKey, endpoint:pubEndpoints[expectedPeerPublicKey.pointee]!)
//						rekeyInfo.isRekeying[peerPublicKey] = true
//					}
//				} catch let error {
//					context.fireErrorCaught(error)
//					promise?.fail(error)
//				}
//			case .encryptedTransit(let publicKey, let payload):
//				guard let ep = pubEndpoints[publicKey] else {
//					logger.critical("no known endpoint for peer", metadata:["public-key_peer":"\(publicKey)"])
//					return
//				}
//				guard let hsg = peerGeometry[publicKey] else {
//					logger.critical("no handshake geometry available", metadata:["public-key_peer":"\(publicKey)"])
//					return
//				}
//				
//				context.writeAndFlush(wrapOutboundOut((ep, .data(payload))), promise:promise)
//			default:
//				return
//		}
//	}
//}

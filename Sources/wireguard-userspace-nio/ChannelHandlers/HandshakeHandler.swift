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
	
	private var logger:Logger
	internal let privateKey:PrivateKey
	
	// Storing public keys for validating responses after we send initiation
	internal var peers:[PeerIndex:PublicKey] = [:]
	internal var peersAddressBook:[Endpoint:PublicKey] = [:]
	
	// Storing initiation packets unless they recieve a valid response
	internal var initiationPackets:[PeerIndex:Message.Initiation.Payload.Authenticated] = [:]
	
	// Precomputed key for the cookie
	internal var precomputedCookieKey:RAW_xchachapoly.Key
	
	// Temp var for testing cookies
	internal var underLoad:Bool = false
	
	// When will the cookies be ready? For the secretCookieR
	internal let ovenTimer:TimeAmount = .seconds(120)
	internal var secretCookieR:Result.Bytes8 = try! generateSecureRandomBytes(as:Result.Bytes8.self)
	
	// Rekey variables
	private var rekeyAttemptTasks: [PeerIndex: RepeatedTask] = [:]
	private var rekeyAttemptsStartTime: [PeerIndex: NIODeadline] = [:]
	
	// Rekey timers
	private let rekeyTimeout: TimeAmount = .seconds(5)
	private let rekeyAttemptTime: TimeAmount = .seconds(90)

	private var _peerSessions:[PeerIndex:PublicKey] = [:]
	
	// Timers for checking incoming initation packets
	internal var initiationTimers:[PeerIndex:TAI64N] = [:]
	private var initiatorEphemeralPrivateKey:[PeerIndex:PrivateKey] = [:]
	private var initiatorChainingData:[PeerIndex:(c:Result.Bytes32, h:Result.Bytes32)] = [:]
	internal init(privateKey pkIn:consuming PrivateKey, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		
		// pre-computing HASH(LABEL-COOKIE || Spub)
		(privateKey, precomputedCookieKey) = withUnsafePointer(to:pkIn) { privateKeyPtr in
			var hasher = try! WGHasher<RAW_xchachapoly.Key>()
			try! hasher.update([UInt8]("cookie--".utf8))
			try! hasher.update(PublicKey(privateKey: privateKeyPtr))
			return (privateKeyPtr.pointee, try! hasher.finish())
		}
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger[metadataKey:"listening_socket"] = "\(context.channel.localAddress!)"
		logger.trace("handler added to pipeline.")
	}
	
	private func generateNewCookieR(context: ChannelHandlerContext) {
		context.eventLoop.scheduleRepeatedTask(initialDelay:ovenTimer, delay:ovenTimer) { [weak self] _ in
			guard let self = self else { return }
			self.secretCookieR = try! generateSecureRandomBytes(as:Result.Bytes8.self)
		}
	}
	
	// Sends the cookie after REKEY-TIMEOUT time
	private func sendCookieInitiation(context:ChannelHandlerContext, endpoint:Endpoint, cookie:Message) {
		context.eventLoop.scheduleTask(in:.seconds(5)) { [weak self, c = ContextContainer(context:context)] in
			guard let self = self else { return }
			c.accessContext { contextPointer in
				contextPointer.pointee.writeAndFlush(wrapOutboundOut((endpoint, cookie)), promise:nil)
			}
		}
	}
	
	// Rekey attempt when initiation doesn't get a valid response
	private func startRekeyAttempts(for peerIndex:PeerIndex, context:ChannelHandlerContext, peerPublicKey:PublicKey, endpoint:Endpoint) {
		guard rekeyAttemptTasks[peerIndex] == nil else { return }
		rekeyAttemptsStartTime[peerIndex] = .now()
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: rekeyTimeout, delay: rekeyTimeout) { [weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			let now = NIODeadline.now()
			guard let start = rekeyAttemptsStartTime[peerIndex],
				now - start < rekeyAttemptTime else {
				rekeyAttemptTasks[peerIndex]?.cancel()
				rekeyAttemptTasks[peerIndex] = nil
				logger.debug("Rekey attempt time expired for peer \(peerIndex)")
				return
			}

			logger.debug("Retrying handshake for peer \(peerIndex) due to timeout")
			c.accessContext { contextPointer in
				contextPointer.pointee.writeAndFlush(wrapOutboundOut((endpoint, .initiation(initiationPackets[peerIndex]!))), promise: nil)
			}
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
				let (pubKey, payload) = unwrapInboundIn(data)
				switch payload {
					// Validate initiation packet and send response upon successfull validation
					case .initiation(let payload):
						logger.debug("received handshake initiation packet")

						// Check if we are under heavy load
						if underLoad {

							do {
								try payload.validateUnderLoadNoNIO(responderStaticPrivateKey: responderPrivateKey, R: secretCookieR, endpoint:endpoint)
							} catch Message.Initiation.Payload.Authenticated.Error.mac2Invalid {
								// Create and send cookie
								let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
								// let packet: PacketType = .cookie(endpoint, cookie)
								context.writeAndFlush(wrapOutboundOut((endpoint, .cookie(cookie)))).whenSuccess { [logger = logger, e = endpoint] in
									logger.debug("cookie reply message sent to endpoint", metadata:["endpoint":"\(e)"])
								}
								return
							} catch Message.Initiation.Payload.Authenticated.Error.mac1Invalid {
								// Ignore the packet, it is invalid
								logger.debug("received invalid handshake initiation packet, ignoring")
								return
							}
						}

						var val = try payload.validate(responderStaticPrivateKey: responderPrivateKey)
						peers[payload.payload.initiatorPeerIndex] = val.initPublicKey
						
						// Check handshake packet time
						if let initiationTime = initiationTimers[payload.payload.initiatorPeerIndex] {
							if(val.timestamp <= initiationTime) {
								return
							}
						}
						initiationTimers[payload.payload.initiatorPeerIndex] = val.timestamp
						
						let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
						let response = try Message.Response.Payload.forge(c:val.c, h:val.h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey)
						let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&val.initPublicKey)
						context.writeAndFlush(wrapOutboundOut((endpoint, .response(authResponse)))).whenSuccess { [logger = logger] in
							logger.debug("handshake response sent to \(endpoint)")
						}
						
						// Pass data for creating transit keys
						let keyPacket:PacketTypeInbound = .keyExchange(val.initPublicKey, endpoint, response.payload.responderIndex, response.c, false)
						_peerSessions[payload.payload.initiatorPeerIndex] = val.initPublicKey
						logger.debug("sending key exhange packet to data handler")
						context.fireChannelRead(wrapInboundOut(keyPacket))
						
					case .response(let payload):
						logger.debug("received handshake response packet", metadata:["remote_address":"\(endpoint)"])
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
								let val = try payload.validate(c:existingC, h:existingH, initiatorStaticPrivateKey:myPrivateKeyPointer, initiatorEphemeralPrivateKey:initiatorEphiPrivateKeyPtr, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
								logger.info("successfully validated handshake response", metadata:["peer_index":"\(payload.payload.initiatorIndex)"])
								
								// Remove held initiation packet
								initiationPackets[payload.payload.initiatorIndex] = nil
								
								// Pass data for creating transit keys
								let packet:PacketTypeInbound = .keyExchange(peerPublicKey, endpoint, payload.payload.responderIndex, val.c, true)
								_peerSessions[payload.payload.initiatorIndex] = peerPublicKey
								logger.debug("Sending key exhange packet to data handler")
								context.fireChannelRead(wrapInboundOut(packet))
								
								// Stop rekey since handshake completed
								rekeyAttemptTasks[payload.payload.initiatorIndex]?.cancel()
								rekeyAttemptTasks[payload.payload.initiatorIndex] = nil
								rekeyAttemptsStartTime[payload.payload.initiatorIndex] = nil
							}
						}
						
					// Received cookie, recreate initiation handshake message with mac2
					case .cookie(let cookiePayload):
						logger.debug("received cookie packet", metadata:["remote_address":"\(endpoint)"])
						guard let peerPublicKey = peersAddressBook[endpoint] else {
							logger.error("no peer public key for \(endpoint)")
							return
						}
						guard let initiationPacket = initiationPackets[cookiePayload.receiverIndex] else {
							logger.error("no retained initiation packet")
							return
						}
						withUnsafePointer(to:privateKey) { privateKey in
							withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
								var phantomCookie:Message.Initiation.Payload.Authenticated
								do {
									phantomCookie = try initiationPacket.payload.finalize(responderStaticPublicKey: expectedPeerPublicKey, cookie: cookiePayload)
									initiationPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
								} catch {
									logger.debug("failed to validate cookie and create msgMac2")
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
						guard let peerPublicKey = _peerSessions[payload.header.receiverIndex] else {
							logger.error("no peer public key for \(payload.header.receiverIndex)")
							return
						}
						logger.debug("Data transit packet sent to data handler")
						context.fireChannelRead(wrapInboundOut(PacketType.encryptedTransit(endpoint, payload)))
				}
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

		let invoke = unwrapOutboundIn(data)
		
		switch invoke {
			case let .initiationInvoker(peerPublicKey):
				guard let endpoint = peersAddressBook[peerPublicKey] else {
					logger.error("no endpoint for peer public key: \(peerPublicKey)")
					return
				}
				do {
					peersAddressBook[endpoint] = peerPublicKey
					try withUnsafePointer(to:privateKey) { privateKey in
						try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
							// Forge initiation packet
							let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey: privateKey, responderStaticPublicKey:expectedPeerPublicKey)
							
							// Store keys and c/h for response
							initiatorEphemeralPrivateKey[payload.initiatorPeerIndex] = ephiPrivateKey
							initiatorChainingData[payload.initiatorPeerIndex] = (c:c, h:h)
							
							// Send initiation packet to packet handler
							logger.debug("successfully forged handshake initiation message", metadata:["peer_endpoint":"\(endpoint)", "peer_public_key":"\(peerPublicKey.debugDescription)"])
							let authPayload = try payload.finalize(responderStaticPublicKey:expectedPeerPublicKey)
							context.writeAndFlush(wrapOutboundOut((endpoint, .initiation(authPayload))), promise:promise)

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
			case .encryptedTransit(let pubKey, let payload):
				logger.debug("Sending transit packet down to packet handler")
				context.writeAndFlush(wrapOutboundOut(PacketTypeInbound.encryptedTransit(pubKey, payload)), promise:promise)
			default:
				return
		}
	}
}

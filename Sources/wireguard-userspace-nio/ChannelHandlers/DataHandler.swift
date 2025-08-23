import NIO
import RAW_dh25519
import Logging
import bedrock_fifo
import wireguard_crypto_core

internal enum InterfaceInstruction {
	// Add peer to pipeline configuration
	case addPeer(PeerInfo)
	// Remove peer from pipeline configuration
	case removePeer(PeerInfo)
	/// indicates a series of bytes that are to be encrypted and sent to the peer
	case encryptAndTransmit(PublicKey, [UInt8])
}

internal enum WireguardEvent {
	case handshakeCompleted(PublicKey, PeerIndex, HandshakeGeometry<PeerIndex>)
	case transitData(PublicKey, PeerIndex, [UInt8])
}

// Handles the data packet encryption and decryption
internal final class DataHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PacketTypeInbound
	internal typealias InboundOut = WireguardEvent
	
	internal typealias OutboundIn = InterfaceInstruction
	internal typealias OutboundOut = PacketTypeOutbound
	
	private var sessionStatus = SessionStatus()
	
	private struct SessionStatus {
		internal var activePeerList:[PublicKey:PeerInfo] = [:]
		internal var activeSessions:[PublicKey:Rotating<HandshakeGeometry<PeerIndex>>] = [:]
		internal var lastHandshake:[PublicKey:NIODeadline] = [:]
	}
		
	// Nsend increments by 1 for every outbound encrypted packet
	// Nrecv used with sliding window to check if packet is valid
	private var nonceCounters:[PeerIndex:(Nsend:Counter, Nrecv:SlidingWindow<Counter>)] = [:]
	private var transmitKeys:[PeerIndex:(Tsend:Result.Bytes32, Trecv:Result.Bytes32)] = [:]
	
	// Active wireguard sessions
	@available(*, deprecated, renamed:"sessionStatus.activeSessions")
	private var sessions:[PublicKey:(previous:PeerIndex?, current:PeerIndex?, next:PeerIndex?)] = [:]
	private var sessionsInv:[PeerIndex:PublicKey] = [:]
	
	// Pending incoming and outgoing packets
	private var pendingWriteFutures:[PublicKey:[(data:[UInt8], promise:EventLoopPromise<Void>?)]] = [:]
	
	// KeepAlive variables
	private var keepaliveTasks:[PeerIndex:RepeatedTask] = [:]
	private var lastOutbound:[PeerIndex:NIODeadline] = [:]

	// KeepAlive interval. Default 25 seconds
	@available(*, deprecated, message:"read the instance property for keepalive directly from the configuration sessionStatus.activePeerList")
	private var keepaliveInterval:[PublicKey:TimeAmount] = [:]
	
	// Re handshake variables
	@available(*, deprecated, renamed:"sessionStatus.lastHandshake")
	private var lastHandshake:[PeerIndex:NIODeadline] = [:]
	private var rehandshakeTasks:[PeerIndex:RepeatedTask] = [:]
	private var nextAllowedReinit:[PeerIndex:NIODeadline] = [:]

	// Re handshake time intervals
	private let rekeyAfterTime:TimeAmount = .seconds(120)
	private let checkEvery:TimeAmount = .seconds(5)
	private let rekeyTimeout:TimeAmount = .seconds(5)
	
	private let logger:Logger

	internal init(logLevel:Logger.Level, initialConfiguration:[Peer]? = nil) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		
		if (initialConfiguration != nil) {
			for peer in initialConfiguration! {
				addPeer(peer:peer)
			}
		}
	}

	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("handler added to NIO pipeline.")
	}

	// MARK: - Keep Alive Task
	private func startKeepalive(for peerIndex:PeerIndex, context:ChannelHandlerContext, peerPublicKey:PublicKey) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		
		guard keepaliveTasks[peerIndex] == nil else {
			return
		}
		guard sessions[peerPublicKey] != nil else {
			return
		}
		let task = context.eventLoop.scheduleRepeatedTask(
			initialDelay:keepaliveInterval[peerPublicKey]!,
			delay:keepaliveInterval[peerPublicKey]!
		) { [weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			let tansportKeysState = transmitKeys[peerIndex]
			var nonceCounterState = nonceCounters[peerIndex]
			guard tansportKeysState != nil, nonceCounterState != nil else {
				return
			}
			// Idle check: only send if no outbound for >= interval.
			let now = NIODeadline.now()
			guard let last = lastOutbound[peerIndex] else {
				return
			}
			guard now - last >= keepaliveInterval[peerPublicKey]! else {
				return
			}
			do {
				let keepalive = try Message.Data.Payload.forge(receiverIndex:peerIndex, nonce:&nonceCounterState!.Nsend, transportKey:tansportKeysState!.Tsend, plainText:[])
				nonceCounters[peerIndex] = nonceCounterState
				c.accessContext { contextPointer in
					contextPointer.pointee.writeAndFlush(wrapOutboundOut(.encryptedTransit(peerPublicKey, keepalive)), promise: nil)
				}

				// Update last outbound for this peer
				lastOutbound[peerIndex] = now
			} catch let error {
				logger.error("keepalive forge/send failed for peer \(peerIndex)", metadata: ["error": "\(error)"])
			}
		}
		keepaliveTasks[peerIndex] = task
	}
	
	private func stopKeepalive(for endpoint:PeerIndex) {
		let task = keepaliveTasks.removeValue(forKey:endpoint)
		if task != nil {
			task!.cancel()
			logger.debug("Stopped keepalive task for peer \(endpoint)")
		}
	}
	
	// MARK: - Re-Handshake Task
	private func startRehandshakeTimer(for peerIndex: PeerIndex, context: ChannelHandlerContext, peerPublicKey: PublicKey) {
		guard rehandshakeTasks[peerIndex] == nil else { return }

		guard sessions[peerPublicKey] != nil else {
			return
		}

		let task = context.eventLoop.scheduleRepeatedTask(
			initialDelay: checkEvery,
			delay: checkEvery
		) { [weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			// we only re-initiate if we have keys and an endpoint
			guard transmitKeys[peerIndex] != nil && nonceCounters[peerIndex] != nil else {
				return
			}
			let now = NIODeadline.now()
			let last = lastHandshake[peerIndex] ?? .uptimeNanoseconds(0)
			// if the current session is older than the soft rekey target, trigger a handshake
			guard now - last >= rekeyAfterTime else {
				return
			}
			// simple rate limiting to avoid storms
			let next = nextAllowedReinit[peerIndex]
			guard next == nil || now >= next! else {
				return
			}
			nextAllowedReinit[peerIndex] = now + rekeyTimeout
			logger.debug("rehandshake trigger for peer \(peerIndex)")
			c.accessContext { contextPointer in
				contextPointer.pointee.writeAndFlush(wrapOutboundOut(.handshakeInitiate(peerPublicKey, nil)), promise:nil)
			}
		}
		rehandshakeTasks[peerIndex] = task
	}
	
	private func stopRehandshake(for endpoint: PeerIndex) {
		if let task = rehandshakeTasks.removeValue(forKey: endpoint) {
			task.cancel()
			logger.debug("stopped rehandshake task for peer \(endpoint)")
		}
		nextAllowedReinit.removeValue(forKey: endpoint)
	}
	
	// Scheduled task to eleminate the `previous` session after 10 seconds
	private func startDeathSentence(for peerIndex: PeerIndex, context: ChannelHandlerContext, delay: TimeAmount = .seconds(10)) {
		context.eventLoop.scheduleTask(in:delay) { [weak self] in
			guard let self = self else { return }
			self.killSession(peerIndex: peerIndex)
			self.logger.debug("session for peerIndex \(peerIndex) killed after delay")
		}
	}

	public func handlerRemoved(context: ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
		for (_, task) in keepaliveTasks { task.cancel() }
		keepaliveTasks.removeAll()
		for (_, task) in rehandshakeTasks { task.cancel() }
		rehandshakeTasks.removeAll()
		nextAllowedReinit.removeAll()
	}
	
	// Helper function for decrypting (authenticating) an encrypted packet
	private func decryptPacket(peerPublicKey: PublicKey, packet:borrowing Message.Data.Payload, transportKey: Result.Bytes32) -> [UInt8]? {
		// Check validity of the nonce
		if (nonceCounters[packet.header.receiverIndex]!.Nrecv.isPacketAllowed(packet.header.counter.RAW_native())) {
			// Authenticate (decrypt) packet
			do {
				let decryptedPacket = try packet.decrypt(transportKey:transportKey)
				return decryptedPacket
			} catch {
				logger.debug("authentication tag failed verification")
				return nil
			}
		} else {
			logger.debug("packet with nonce not allowed")
			return nil
		}
	}
	
	private func addPeer(peer:PeerInfo) {
		if (peer.internalKeepAlive != nil) {
			keepaliveInterval[peer.publicKey] = peer.internalKeepAlive
		} else {
			keepaliveInterval[peer.publicKey] = .seconds(25)
		}
		sessionStatus.activePeerList[peer.publicKey] = peer
	}
	
	private func removePeer(peer: PeerInfo) {
		keepaliveInterval[peer.publicKey] = nil
		sessionStatus.activePeerList.removeValue(forKey:peer.publicKey)
	}
	
	// Specifically kills and removes the `previous` session
	@available(*, deprecated)
	private func removePreviousSession(peerPublicKey: PublicKey) {
		guard let peerSessions = sessions[peerPublicKey] else { return }
		guard let previous = peerSessions.previous else { return }
		
		killSession(peerIndex: previous)
		sessions[peerPublicKey]!.previous = nil
	}
	
	// Rotates sessions to the left (nil <- previous <- current <- next)
	@available(*, deprecated)
	private func rotateSessions(peerPublicKey: PublicKey, context: ChannelHandlerContext) {
		removePreviousSession(peerPublicKey: peerPublicKey)
		guard let peerSessions = sessions[peerPublicKey] else { return }
		sessions[peerPublicKey]!.previous = peerSessions.current
		sessions[peerPublicKey]!.current = peerSessions.next
		sessions[peerPublicKey]!.next = nil
		if let prev = sessions[peerPublicKey]!.previous {
			stopKeepalive(for: prev)
			stopRehandshake(for: prev)
			startDeathSentence(for: prev, context: context)
		}
	}
	
	// Kills a single session
	private func killSession(peerIndex: PeerIndex) {
		// Set the session to nil in the sessions for the peer
		if let publicKey = sessionsInv[peerIndex],
		   var session = sessions[publicKey] {
			if session.previous == peerIndex {
				session.previous = nil
			}
			if session.current == peerIndex {
				session.current = nil
			}
			if session.next == peerIndex {
				session.next = nil
			}
			sessions[publicKey] = session
		}
		
		// Remove everything related to the session
		sessionsInv.removeValue(forKey:peerIndex)
		nonceCounters.removeValue(forKey:peerIndex)
		transmitKeys.removeValue(forKey:peerIndex)
		lastOutbound.removeValue(forKey:peerIndex)
		lastHandshake.removeValue(forKey:peerIndex)
		
		stopKeepalive(for: peerIndex)
		stopRehandshake(for: peerIndex)
	}
	
	// Kills all active sessions for a peer (previous, current, next)
	private func killAllSessions(peerPublicKey: PublicKey) {
		guard let peerSessions = sessions[peerPublicKey] else { return }
		if peerSessions.0 != nil {
			killSession(peerIndex: peerSessions.0!)
		}
		if peerSessions.1 != nil {
			killSession(peerIndex: peerSessions.1!)
		}
		if peerSessions.2 != nil {
			killSession(peerIndex: peerSessions.2!)
		}
		sessions.removeValue(forKey: peerPublicKey)
		logger.debug("killed all sessions for \(peerPublicKey)")
	}
	
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		do {
			var logger = logger
			switch unwrapInboundIn(data) {
				// Decrypt the payload or send initiation message if unable to decrypt
				case .encryptedTransit(let publicKey, let peerIndex, let geometry, let payload):
					logger[metadataKey:"public-key_peer"] = "\(publicKey)"

					// Authenticate packet, else drop packet
					guard let decryptedPacket = decryptPacket(peerPublicKey: publicKey, packet: payload, transportKey: transmitKeys[peerIndex]!.Trecv) else {
						return
					}
					
					/* BEGIN THIS CAN BE DELETED */
					if let next = sessions[publicKey]!.next {
						if (next == peerIndex) {
							rotateSessions(peerPublicKey: publicKey, context: context)
						}
					}
					/* END THIS CAN BE DELETED */
					
					switch sessionStatus.activeSessions[publicKey] {
						case .some(var statusVal):
							guard statusVal.next?.m == geometry.mp else {
								break
							}
							logger.trace("inbound data packet matched with peer index in rotational `next` position")
							statusVal.rotate()
							sessionStatus.lastHandshake[publicKey] = .now()
							context.fireChannelRead(wrapInboundOut(.handshakeCompleted(publicKey, peerIndex, sessionStatus.activeSessions[publicKey]!.next!)))
							startKeepalive(for: peerIndex, context: context, peerPublicKey: publicKey)
							startRehandshakeTimer(for: peerIndex, context: context, peerPublicKey: publicKey)
						case .none:
							return
					}
					
					// Make sure the packet is not a keep alive packet
					guard (decryptedPacket.isEmpty == false) else {
						logger.debug("received keepalive packet")
						return
					}
					
					// Send plaintext packet to the kcp handler
					context.fireChannelRead(wrapInboundOut(.transitData(publicKey, peerIndex, decryptedPacket)))
				
				// Calculate transmit keys and set nonce counters to 0
				case .keyExchange(let peerPublicKey, let peerIndex, let c, let isInitiator, let geometry):
					context.fireChannelRead(wrapInboundOut(.handshakeCompleted(peerPublicKey, peerIndex, geometry)))
					
					logger.debug("received key exchange info")
					
					try withUnsafePointer(to:c) { cPtr in
						switch geometry {
							case .selfInitiated(m:let m, mp:let mp):
								// switch that checks if there is already a session value in the dictionary
								switch sessionStatus.activeSessions[peerPublicKey] {
									case .some(var session):
										session.rotate(replacingNext:geometry)
										sessionStatus.activeSessions[peerPublicKey] = session
									case .none:
										sessionStatus.activeSessions[peerPublicKey] = Rotating(current:geometry)
								}
 							case .peerInitiated(m:let m, mp:let mp):
 								// switch that checks if there is already a session value in the dictionary
 								switch sessionStatus.activeSessions[peerPublicKey] {
 									case .some(var session):
 									
 										// switch that checks if there is a next session occupying the stored session
 										switch session.next {
 											case .some(var nextSession):
 												// kill any session based on the currently stored next value
 												killSession(peerIndex:nextSession.mp)
 												// replace the next position of the session rotation with the new geometry
 												_ = session.apply(next:geometry)
 												
 											case .none:
												_ = session.apply(next:geometry)
 										}
 										
										// assign the modified session value back into the dictionary
										sessionStatus.activeSessions[peerPublicKey] = session

 									case .none:
 										// assign the new session value into the dictionary
										sessionStatus.activeSessions[peerPublicKey] = Rotating(next:geometry)
 										break
 								}
						}
						
						/* BEGIN THIS CAN BE DELETED */
						if (isInitiator) {
							if (sessions[peerPublicKey] == nil) {
								sessions[peerPublicKey] = (nil, peerIndex, nil)
							} else {
								rotateSessions(peerPublicKey:peerPublicKey, context:context)
								sessions[peerPublicKey]!.current = peerIndex
							}
						} else {
							if (sessions[peerPublicKey] == nil) {
								sessions[peerPublicKey] = (nil, nil, peerIndex)
							} else {
								if (sessions[peerPublicKey]!.next == nil) {
									sessions[peerPublicKey]!.next = peerIndex
								} else { 
									killSession(peerIndex:sessions[peerPublicKey]!.next!)
									sessions[peerPublicKey]!.next = peerIndex
								}
							}
						}
						/* END THIS CAN BE DELETED */
						
						sessionsInv[peerIndex] = peerPublicKey
						
						// Initialize nonce counters
						nonceCounters[peerIndex] = (Nsend:0, Nrecv:SlidingWindow<Counter>(windowSize: 64))
						
						// Calculate transmit keys
						let (lhs, rhs) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)
						if (isInitiator) {
							transmitKeys[peerIndex] = (lhs, rhs)
						} else {
							transmitKeys[peerIndex] = (rhs, lhs)
						}
						logger.info("transmit keys calculated")
					
						// Start session timers (keep alive, re-handshake timer, ...)
						
						if (isInitiator) {
							lastHandshake[peerIndex] = .now()
							startKeepalive(for: peerIndex, context: context, peerPublicKey:peerPublicKey)
							startRehandshakeTimer(for: peerIndex, context: context, peerPublicKey: peerPublicKey)
						}
						
						// Handle encrypting packets waiting on handshake completion
						guard let packets = pendingWriteFutures[peerPublicKey] else {
							return
						}
						for packet in packets {
							if let hsGeometry = sessionStatus.activeSessions[peerPublicKey]!.current {
								let (peerM, peer) = (hsGeometry.m, hsGeometry.mp)
								let encryptedPacket = try Message.Data.Payload.forge(receiverIndex:peer, nonce:&nonceCounters[peer]!.Nsend, transportKey:transmitKeys[peer]!.Tsend, plainText:packet.data)
								context.write(wrapOutboundOut(PacketTypeOutbound.encryptedTransit(peerPublicKey, encryptedPacket)), promise:packet.promise)
								lastOutbound[peerIndex] = .now()
							}
						}
						context.flush()
						pendingWriteFutures[peerPublicKey] = nil
					}
				default:
					return
			}
		} catch {
			logger.error("error processing data packet: \(error)")
			context.fireErrorCaught(error)
		}
		
	}
	
	// Handles writing inbound data into an encrypted transit packet
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		switch unwrapOutboundIn(data) {
			case .addPeer(let peer):
				addPeer(peer: peer)
			case .removePeer(let peer):
				removePeer(peer: peer)
			case .encryptAndTransmit(let publicKey, let bytes):
				guard let ep = sessionStatus.activePeerList[publicKey]?.endpoint else {
					logger.error("no endpoint found for peer", metadata:["public-key_peer":"\(publicKey)"])
					return
				}
				// Encrypt packet and send it out to peer
				do {
					if let peerIndex = sessions[publicKey] {
						let encryptedPacket = try Message.Data.Payload.forge(receiverIndex: peerIndex.current!, nonce: &nonceCounters[peerIndex.current!]!.Nsend, transportKey: transmitKeys[peerIndex.current!]!.Tsend, plainText: bytes)
						context.writeAndFlush(wrapOutboundOut(PacketTypeOutbound.encryptedTransit(publicKey, encryptedPacket)), promise:promise)
						lastOutbound[peerIndex.current!] = .now()
					} else {
						// Add packet to be encrypted after handshake
						pendingWriteFutures[publicKey, default: []].append((bytes, promise))

						// Send handshake since there is no active session
						context.writeAndFlush(wrapOutboundOut(PacketTypeOutbound.handshakeInitiate(publicKey, ep)), promise:nil)
					}
				} catch {
					logger.debug("unable to encrypt incoming data into a transit packet")
					context.fireErrorCaught(error)
				}
		}
	}
		
	// Finish the queue when channel shuts down
	internal func channelInactive(context: ChannelHandlerContext) {
		// there used to be some code here but it has since been removed and now this function does nothing.
	}
}

import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo {
	/// used to represent and store all live information about a peer that is needed for active communication on the socket.
	internal final class Live:@unchecked Sendable {
		/// the logger that the live peer info instance uses
		private let log:Logger
		private let wireguardHandler:WireguardHandler

		// standard configuration stuff
		/// the public key of the remote peer
		internal let publicKey:PublicKey
		/// the endpoint that the peer is known to be reachable at
		private var ep:Endpoint?
		internal var persistentKeepalive:TimeAmount?

		// handshake initiation
		private var selfInitiatedKeys:CurrentSelfInitiatedInfo

		/// thrown when pending data could not be written because the handshake rekey attempt time was exceeded
		internal struct RekeyAttemptTimeExceeded:Swift.Error {}
		private var handshakeInitiationTask:(NIODeadline, RepeatedTask)? = nil {
			didSet {
				oldValue?.1.cancel()
			}
		}
		// packets that need to be sent after a handshake is complete
		private var postHandshakePackets = PendingPostHandshake()

		// cryptokey rotation
		private var rotation:Rotating<Session>

		private var rekeyAttemptTimeNow:NIODeadline? = nil

		internal init(_ peerInfo:PeerInfo, handler:WireguardHandler, context:borrowing ChannelHandlerContext, logLevel:Logger.Level) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif

			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_peer"] = "\(peerInfo.publicKey)"
			log = buildLogger

			publicKey = peerInfo.publicKey
			ep = peerInfo.endpoint
			persistentKeepalive = peerInfo.internalKeepAlive
			rotation = Rotating<Session>()

			let um = handler
			wireguardHandler = um
			selfInitiatedKeys = CurrentSelfInitiatedInfo(responderStaticPublicKey:peerInfo.publicKey, handler:um)
			buildLogger.trace("created live peer info instance.")
		}
				
		deinit {
			handshakeInitiationTask = nil
			log.trace("instance deinitialized.")
		}
	}
}

// MARK: Send
extension PeerInfo.Live {
	/// used to express the strategy for sending data to a peer. data can be sent to a peer in one of three ways, and this enum expresses which way should be used.
	internal enum SendStrategy {
		/// the values that should be used to send the data immediately
		internal struct Values {
			/// the n value to use for sending
			internal var nSend:Counter
			/// the t value to use for sending
			internal let tSend:Result.Bytes32
			/// the session data that should be used for sending
			internal let session:Session
		}
		/// returned when there is a current session that has not crossed its timeout threshold.
		case sendImmediately(Values)
		/// returned when there is no current session and a handshake initiation is actively taking place.
		case queueForInitiatingHandshake
		/// returned when there is no current session but there is a next session awaiting a key rotation into the current one.
		case queueWhileAwaitingKeyRotation
	}

	/// called when it is time to transmit data to the remote peer but the transit keys to use for this transmission are not yet known.
	internal func getSendStrategy(context:borrowing ChannelHandlerContext, now:NIODeadline, initiationValues:(mStaticPrivateKey:MemoryGuarded<PrivateKey>, endpointOverride:Endpoint?)) -> SendStrategy {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		rekeyAttemptTimeNow = now
		func guardCaught() -> SendStrategy {
			switch rotation.next {
				case .some(let nextSesh):
					guard nextSesh.establishedDate + WireguardHandler.rejectAfterTime > now else {
						// the next session has expired, we need to initiate a new handshake
						try? launchHandshakeInitiationTask(context:context, now:now, initiatorStaticPrivateKey:initiationValues.mStaticPrivateKey)
						return .queueForInitiatingHandshake
					}
					return .queueWhileAwaitingKeyRotation
				case .none:
					// there is no current session or next session, so we need to initiate a handshake
					try? launchHandshakeInitiationTask(context:context, now:now, initiatorStaticPrivateKey:initiationValues.mStaticPrivateKey)
					return .queueForInitiatingHandshake
			}
		}
		guard let currentRotation = rotation.current else {
			return guardCaught()
		}
		guard currentRotation.establishedDate + WireguardHandler.rejectAfterTime > now else {
			return guardCaught()
		}
		return .sendImmediately(.init(nSend:currentRotation.nVar.valueSend, tSend:currentRotation.tVar.valueSend, session:currentRotation))
	}

	internal func updateSendValues(context:borrowing ChannelHandlerContext, now:NIODeadline, _ sendValues:SendStrategy.Values, initiationValues:(mStaticPrivateKey:MemoryGuarded<PrivateKey>, endpointOverride:Endpoint?)) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		guard var currentSession = rotation.current else {
			fatalError("no active handshakes")
		}
		guard currentSession.geometry.m == sendValues.session.geometry.m else {
			fatalError("updating nSend on a session that is not current")
		}
		switch currentSession.geometry {
			case .selfInitiated(m:let m, mp:let mp):
				// check for the passive rehandshake threshold
				if currentSession.establishedDate + WireguardHandler.rekeyAfterTime <= now {
					try? launchHandshakeInitiationTask(context:context, now:now, initiatorStaticPrivateKey:initiationValues.mStaticPrivateKey)
				}
			default:
				break
		}
		currentSession.nVar.valueSend = sendValues.nSend
		rotation.current = currentSession
	}
	
	internal borrowing func queuePostHandshake(context:ChannelHandlerContext, data:ByteBuffer, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		postHandshakePackets.queue(data:data, promise:promise)
	}
}

// MARK: Receive
extension PeerInfo.Live {
	/// called to retrieve the receive variables for a specific session.
	internal borrowing func getRecvVars(context:borrowing ChannelHandlerContext, geometry inputPositionExplicit:Rotating<Session>.Positioned, now:NIODeadline) -> (nRecv:SlidingWindow<Counter>, tRecv:Result.Bytes32)? {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let element = inputPositionExplicit.element
		guard element.establishedDate + WireguardHandler.rejectAfterTime > now else {
			log.debug("unable to use session because it has expired", metadata:["session_id":"\(element.geometry)"])
			return nil
		}
		return (nRecv:element.nVar.valueRecv, tRecv:element.tVar.valueRecv)
	}

	/// called after bytes have been received. updates various counters and schedules any tasks as needed.
	internal borrowing func nRecvUpdate(context:borrowing ChannelHandlerContext, now:NIODeadline, _ newValue:SlidingWindow<Counter>, geometry inputPositionExplicit:Rotating<Session>.Positioned, mStaticPrivateKey ourStaticPrivateKey:borrowing MemoryGuarded<PrivateKey>) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		logger.trace("updating nRecv value for session", metadata:["session_id":"\(inputPositionExplicit.element.geometry)"])
		switch inputPositionExplicit {
			case .current(let element):
				// switch to evaluate if the current session has crossed the passive rehandshake threshold
				switch element.geometry {
					case .selfInitiated(m:_, mp:_):
						// passive rehandshake evaluation
						if (element.establishedDate + (WireguardHandler.rejectAfterTime - WireguardHandler.keepaliveTimeout - WireguardHandler.rekeyTimeout)) <= now && handshakeInitiationTask == nil {
							try? launchHandshakeInitiationTask(context:context, now:now, initiatorStaticPrivateKey:ourStaticPrivateKey)
						}
					case .peerInitiated(m:_, mp:_):
						// passive handshakes cannot be sent in the responder role
						break;
				}
				rotation.current!.nVar.valueRecv = newValue
			case .previous(_):
				rotation.previous!.nVar.valueRecv = newValue
			case .next(let element):
				guard case .peerInitiated(m:_, mp:_) = element.geometry else {
					fatalError("using \"next\" session slot with unexpected geometry type (self initiated). this is a critical internal error. \(#file):\(#line)")
				}
				rotation.next!.nVar.valueRecv = newValue
				context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(sessionStartDate:now, publicKey:publicKey, geometry:element.geometry))
				applyRotation(context:context, now:now)
				if rotation.previous == nil {
					while var nextPacket = postHandshakePackets.dequeue() {
						logger.trace("writing post-handshake queued packet after applying key rotation.", metadata:["size":"\(nextPacket.data.readableBytes) bytes"])
						wireguardHandler.writeBytes(context: context, publicKey: publicKey, payload: &nextPacket.data, promise: nextPacket.promise)
					}
				}
		}
	}
}

// MARK: Initiation
extension PeerInfo.Live {
	/// thrown when a handshake initiation task is already running, not yet timed out, but another is attempted to be launched
	internal struct HandshakeTaskAlreadyRunning:Swift.Error {}
	/// thrown when no endpoint is known for the remote peer
	internal struct UnknownPeerEndpoint:Swift.Error {}
	/// thrown when a rekey attempt is made too soon after the previous attempt
	internal struct RekeyAttemptTooSoon:Swift.Error {}

	/// begins the repeated task that sends handshake initiations to the remote peer. the endpoint for the remote peer can be optionally overridden for the initiations that are sent.
	/// - parameters:
	/// 	- context: the channel handler context
	/// 	- now: the current time
	/// 	- epOverride: an optional endpoint override
	/// 	- initiatorStaticPrivateKey: the initiator's static private key
	/// - throws:
	/// 	- `HandshakeTaskAlreadyRunning` if a handshake initiation task is already running
	/// 	- `UnknownPeerEndpoint` if no endpoint is known for the remote peer
	/// 	- `RekeyAttemptTooSoon` if a rekey attempt is made too soon after the previous attempt
	internal func launchHandshakeInitiationTask(context:ChannelHandlerContext, now:NIODeadline, initiatorStaticPrivateKey:MemoryGuarded<PrivateKey>) throws {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		// verify that an initiation task does not already exist.
		guard handshakeInitiationTask == nil else {
			logger.trace("handshake initiation task could not be created because an existing task is already running.")
			throw HandshakeTaskAlreadyRunning()
		}
		// determine which endpoint to use for initiating a connection with the peer
		let targetEndpoint:Endpoint
		guard ep != nil else {
			// fail because no endpoint is known. this is a user error so no need to `fireErrorCaught`.
			logger.warning("cannot launch handshake initiation task because no endpoint is known for the remote peer.")
			throw UnknownPeerEndpoint()
		}
		// use the value that came from the peer list
		targetEndpoint = ep!
		logger[metadataKey:"endpoint_remote"] = "\(targetEndpoint)"
		logger.trace("using stored endpoint for handshake initiation with remote peer.")
		guard (rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > now else {
			// a rekey attempt was made recently, do not send another handshake initiation
			logger.debug("skipping handshake initiation emission due to recent rekey attempt.", metadata:["rekey_attempt_time":"\(String(describing:rekeyAttemptTimeNow))", "current_time":"\(now)"])
			throw RekeyAttemptTooSoon()
		}
		let useInitialDelay = selfInitiatedKeys.handshakeRekeyDelay(context:context, now:now) ?? .seconds(0)
		let usePeerIndex = try generateSecureRandomBytes(as:PeerIndex.self)
		logger.trace("launching handshake initiation task to write outbound handshake message.", metadata:["initial_delay":"\(useInitialDelay)", "index_initiator":"\(usePeerIndex)"])
		handshakeInitiationTask = (now, context.eventLoop.scheduleRepeatedTask(initialDelay:useInitialDelay, delay:WireguardHandler.rekeyTimeout, { [weak self, ipk = initiatorStaticPrivateKey, pubKey = publicKey, cc = ContextContainer(context:context), toEP = targetEndpoint, l = logger, upi = usePeerIndex] _ in
			guard let self = self else { return }
			let currentTime = NIODeadline.now()
			guard (self.rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > currentTime else {
				// rekey time has passed, we can no longer attempt to make handshake initiations
				l.debug("halting handshake initiation emission. rekey attempt time exceeded.", metadata:["rekey_attempt_time":"\(String(describing:self.rekeyAttemptTimeNow))", "current_time":"\(currentTime)"])
				
				// cancel the recurring task
				self.handshakeInitiationTask = nil
				throw RekeyAttemptTimeExceeded()
			}
			do {
				try cc.accessContext { contextPtr in
					try withUnsafePointer(to:pubKey) { pubKeyPtr in

						l.trace("transmitting handshake initiation message to remote peer.", metadata:["public-key_remote":"\(pubKey)"])

						// forge the authenticated message
						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:ipk, responderStaticPublicKey:pubKeyPtr, initiatorPeerIndex:upi)
						let authenticatedPayload = try payload.finalize(responderStaticPublicKey:pubKeyPtr)
						
						// install the resulting crypto keys in the self initiated key storage
						self.selfInitiatedKeys.installInitiation(context:contextPtr.pointee, now:currentTime, initiatorEphemeralPrivateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)
						
						// encode the initiation and send it on the socket
						let handshakeInitiationMessage:Message = .initiation(authenticatedPayload)
						var encodedLength = 0
						handshakeInitiationMessage.RAW_encode(count:&encodedLength)
						var encBuffer = wireguardHandler.encodeBuffer!
						encBuffer.clear(minimumCapacity:encodedLength)
						encBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:encodedLength) { (ptr:UnsafeMutableRawBufferPointer) -> Int in
							return ptr.baseAddress!.distance(to:handshakeInitiationMessage.RAW_encode(dest:ptr.baseAddress!.assumingMemoryBound(to:UInt8.self)))
						}
						contextPtr.pointee.write(wireguardHandler.wrapOutboundOut(AddressedEnvelope<ByteBuffer>(remoteAddress:SocketAddress(toEP), data:encBuffer))).whenComplete { [l = l] result in
							switch result {
								case .success():
									l.trace("transmitted handshake initiation message.", metadata:["public-key_remote":"\(pubKey)"])
								case .failure(let error):
									l.error("error occurred while transmitting handshake initiation message: '\(String(describing:error))'", metadata:["public-key_remote":"\(pubKey)"])
							}
						}
						wireguardHandler.flushOutbound(context:contextPtr.pointee, force:true)
					}
				}
			} catch let error {
				// fire the error into the channel and cancel the handshake task
				cc.accessContext { contextPtr in
					l.error("error occurred during handshake initiation task: '\(String(describing:error))'", metadata:["public-key_remote":"\(pubKey)"])
					contextPtr.pointee.fireErrorCaught(error)
				}
				self.handshakeInitiationTask = nil
			}
		}))
	}

	/// extracts a pending handshake initiation from memory so it can be processed and upgraded to a full session.
	internal borrowing func handshakeInitiationResponse(context:ChannelHandlerContext, now:NIODeadline, initiatorPeerIndex:PeerIndex) -> (initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? {
		return selfInitiatedKeys.claimInitiation(context: context, now: now, initiatorPeerIndex:initiatorPeerIndex)
	}
}

// MARK: Accessing Sessions
extension PeerInfo.Live {
	/// returns the session (and its rotational position) for the given peer index
	/// - parameters
	/// 	- peerM: the peer index m value to search for
	/// - returns: the positioned session if found, otherwise nil
	internal borrowing func session(forPeerM peerM:PeerIndex) -> Rotating<Session>.Positioned? {
		// check the current position
		switch rotation.current {
			case .some(let session):
				guard session.geometry.m != peerM else {
					return .current(session)
				}
				fallthrough
			case .none:
				// current position does not match. check the previous position
				switch rotation.previous {
					case .some(let session):
						guard session.geometry.m != peerM else {
							return .previous(session)
						}
						fallthrough
					case .none:
						// previous position does not match. check the next position
						switch rotation.next {
							case .some(let session):
								guard session.geometry.m != peerM else {
									return .next(session)
								}
								fallthrough
							case .none:
								// no matching geometry found
								return nil
						}
				}
		}
	}
}

// MARK: Handshake Apply
extension PeerInfo.Live {
	/// called when a peer initiated handshake is received and a response is going to be sent out. the provided c value pointer is used to derive the handshake keys.
	internal func applyPeerInitiated(context:borrowing ChannelHandlerContext, now:NIODeadline, _ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws {
		var logger = log
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		guard case .peerInitiated(m:_, mp:_) = element else {
			fatalError("self initiated geometry used on peer initiated function. this is a critical internal error. \(#file):\(#line)")
		}
		#endif
		
		// generate the transmit keys
		let kdfResults = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)
		logger.debug("transmit keys generated from peer initiated handshake")

		// add the new index to the active indicies
		let wgh = wireguardHandler
		wgh.automaticallyUpdatedVariables.activeSessionIndicies.add(indexM:element.m, publicKey:publicKey)
		
		// handle the session that falls out of the rotation
		guard let outgoingIndexValue = rotation.apply(next:Session(geometry:element, nVar:SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), tVar:SendReceive<Result.Bytes32, Result.Bytes32>(peerInitiated:kdfResults), establishedDate:now)) else {
			// no outgoing index value, return
			return
		}
		wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingIndexValue.geometry.m)

		// cancel the scheduled handshake initiation task
		handshakeInitiationTask = nil
	}

	/// called when a handshake response is received for a self initiated handshake.
	internal func applySelfInitiated(context:borrowing ChannelHandlerContext, now:NIODeadline, _ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws {
		var logger = log
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		guard case .selfInitiated(m:_, mp:_) = element else {
			fatalError("peer initiated geometry used on self initiated function. this is a critical internal error. \(#file):\(#line)")
		}
		#endif

		// generate the transmit keys
		let kdfResults = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)
		logger.debug("transmit keys generated from self initiated handshake")

		// apply the rotation of the existing sessions with the new session
		let rotationResults = rotation.rotate(replacingNext:Session(geometry:element, nVar:SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), tVar:SendReceive<Result.Bytes32, Result.Bytes32>(selfInitiated:kdfResults), establishedDate:now))
		
		// automatically update the wireguard handler as needed
		if let outgoingPrevious = rotationResults.previous {
			wireguardHandler.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingPrevious.geometry.m)
		}
		if let outgoingNext = rotationResults.next {
			wireguardHandler.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingNext.geometry.m)
		}
		wireguardHandler.automaticallyUpdatedVariables.activeSessionIndicies.add(indexM:element.m, publicKey:publicKey)

		// fire the handshake information to the channel
		context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(sessionStartDate:now, publicKey:publicKey, geometry: element))

		// flush any pending data
		while var (pendingPacket) = postHandshakePackets.dequeue() {
			logger.trace("flushing queued post-handshake packet", metadata:["public-key_remote":"\(publicKey)"])
			wireguardHandler.writeBytes(context:context, publicKey:publicKey, payload:&pendingPacket.data, promise:pendingPacket.promise)
		}
		
		// cancel the scheduled handshake initiation task
		handshakeInitiationTask = nil
	}
}

// MARK: Session Rotation
extension PeerInfo.Live {
	/// executes a rotational transformation on the current operating trio of cryptographic keys
	fileprivate borrowing func applyRotation(context:borrowing ChannelHandlerContext, now:NIODeadline) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.debug("applying rotation to active cryptokey set. next -> current -> previous.")
		guard let outgoingID = rotation.rotate() else {
			return
		}
		wireguardHandler.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingID.geometry.m)
	}
}

// MARK: Endpoint
extension PeerInfo.Live {
	/// retrieve the previously known endpoint for the peer
	/// - returns: the endpoint that the peer has been observed at
	internal borrowing func endpoint() -> Endpoint? {
		return ep
	}

	/// journal the endpoint that the peer has been observed at
	/// - parameter inputEndpoint: the new endpoint value that the peer was observed at
	internal borrowing func updateEndpoint(_ inputEndpoint:Endpoint) {
		guard ep != inputEndpoint else {
			return
		}
		ep = inputEndpoint
		log.info("peer roamed to new endpoint", metadata:["endpoint_remote":"\(inputEndpoint)"])
	}
}

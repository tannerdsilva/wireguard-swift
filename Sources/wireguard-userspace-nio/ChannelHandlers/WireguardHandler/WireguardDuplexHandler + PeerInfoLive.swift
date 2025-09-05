import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo {
	internal final class Live {
		private let log:Logger
		private let wireguardHandler:Unmanaged<WireguardHandler>

		// standard configuration stuff
		/// the public key of the remote peer
		internal let publicKey:PublicKey
		/// the endpoint that the peer is known to be reachable at
		private var ep:Endpoint? {
			didSet {
				if ep != nil {
					ap = SocketAddress(ep!)
				} else {
					ap = nil
				}
			}
		}
		private var ap:SocketAddress?
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

			let um = Unmanaged.passUnretained(handler)
			wireguardHandler = um
			selfInitiatedKeys = CurrentSelfInitiatedInfo(responderStaticPublicKey:peerInfo.publicKey, handler:um)
		}

		internal func getSendVars(context:ChannelHandlerContext, now:NIODeadline, initiationValues:(mStaticPrivateKey:MemoryGuarded<PrivateKey>, endpointOverride:Endpoint?)) -> (nSend:Counter, tSend:Result.Bytes32, session:Session)? {
			rekeyAttemptTimeNow = now
			guard let currentRotation = rotation.current else {
				// there is no current rotation so we need to initiate a handshake
				try? launchHandshakeInitiationTask(context:context, now:now, endpointOverride:initiationValues.endpointOverride, initiatorStaticPrivateKey:initiationValues.mStaticPrivateKey)
				return nil
			}
			return (nSend:currentRotation.nVar.valueSend, tSend:currentRotation.tVar.valueSend, session:currentRotation)
		}

		internal func nSendUpdate(context:ChannelHandlerContext, now:NIODeadline, _ nSend:Counter, initiationValues:(mStaticPrivateKey:MemoryGuarded<PrivateKey>, endpointOverride:Endpoint?)) {
			guard var currentSession = rotation.current else {
				fatalError("no active handshakes")
			}
			switch currentSession.geometry {
				case .selfInitiated(m:let m, mp:let mp):
					// check for the passive rehandshake threshold
					if currentSession.establishedDate + WireguardHandler.rekeyAfterTime <= now {
						try? launchHandshakeInitiationTask(context:context, now:now, endpointOverride:initiationValues.endpointOverride, initiatorStaticPrivateKey:initiationValues.mStaticPrivateKey)
					}
				default:
					break
			}
			currentSession.nVar.valueSend = nSend
			rotation.current = currentSession
		}
		
		internal borrowing func queuePostHandshake(context:ChannelHandlerContext, data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			postHandshakePackets.queue(data:data, promise:promise)
		}

		internal borrowing func getRecvVars(geometry inputPositionExplicit:Rotating<Session>.Positioned) -> (nRecv:SlidingWindow<Counter>, tRecv:Result.Bytes32)? {
			switch inputPositionExplicit {
				case .current(let element):
					return (nRecv:element.nVar.valueRecv, tRecv:element.tVar.valueRecv)
				case .previous(let element):
					return (nRecv:element.nVar.valueRecv, tRecv:element.tVar.valueRecv)
				case .next(let element):
					return (nRecv:element.nVar.valueRecv, tRecv:element.tVar.valueRecv)
			}
		}

		internal borrowing func nRecvUpdate(context:borrowing ChannelHandlerContext, now:NIODeadline, _ newValue:SlidingWindow<Counter>, geometry inputPositionExplicit:Rotating<Session>.Positioned, mStaticPrivateKey ourStaticPrivateKey:borrowing MemoryGuarded<PrivateKey>) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			switch inputPositionExplicit {
				case .current(let element):
					switch element.geometry {
						case .selfInitiated(m:_, mp:_):
							// passive rehandshake evaluation
							if (element.establishedDate + (WireguardHandler.rejectAfterTime - WireguardHandler.keepaliveTimeout - WireguardHandler.rekeyTimeout)) <= now && handshakeInitiationTask == nil {
								try? launchHandshakeInitiationTask(context:context, now:now, endpointOverride:nil, initiatorStaticPrivateKey:ourStaticPrivateKey)
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
					applyRotation(context:context, now:now)
			}
		}
	}
}

// MARK: Handshake Initiation
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
	internal func launchHandshakeInitiationTask(context:ChannelHandlerContext, now:NIODeadline, endpointOverride epOverride:Endpoint?, initiatorStaticPrivateKey:MemoryGuarded<PrivateKey>) throws {
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
		if epOverride != nil {
			// use the value that came from OutboundIn. do not document this endpoint until it is discovered in the response to this initiation.
			targetEndpoint = epOverride!
			logger[metadataKey:"endpoint_remote"] = "\(targetEndpoint)"
			logger.trace("overriding stored endpoint for handshake initiation")
		} else if ep != nil {
			// use the value that came from the peer list
			targetEndpoint = ep!
			logger[metadataKey:"endpoint_remote"] = "\(targetEndpoint)"
			logger.trace("using stored endpoint for handshake initiation")
		} else {
			// fail because no endpoint is known. this is a user error so no need to `fireErrorCaught`.
			logger.warning("cannot launch handshake initiation task because no endpoint is known for the remote peer")
			throw UnknownPeerEndpoint()
		}

		guard (rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > now else {
			// a rekey attempt was made recently, do not send another handshake initiation
			logger.debug("skipping handshake initiation emission due to recent rekey attempt", metadata:["rekey_attempt_time":"\(String(describing:rekeyAttemptTimeNow))", "current_time":"\(now)"])
			throw RekeyAttemptTooSoon()
		}
		let useInitialDelay = selfInitiatedKeys.handshakeRekeyDelay(context:context, now:now) ?? .seconds(0)
		let usePeerIndex = try generateSecureRandomBytes(as:PeerIndex.self)
		logger.trace("launching handshake initiation task to write outbound handshake message", metadata:["initial_delay":"\(useInitialDelay)", "index_initiator":"\(usePeerIndex)"])
		handshakeInitiationTask = (now, context.eventLoop.scheduleRepeatedTask(initialDelay:useInitialDelay, delay:WireguardHandler.rekeyTimeout, { [weak self, ipk = initiatorStaticPrivateKey, pubKey = publicKey, cc = ContextContainer(context:context), toEP = targetEndpoint, l = logger, upi = usePeerIndex] _ in
			guard let self = self else { return }
			let currentTime = NIODeadline.now()
			guard (self.rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > currentTime else {
				// rekey time has passed, we can no longer attempt to make handshake initiations
				l.debug("skipping handshake initiation emission due to recent rekey attempt outside of the recurring task")
				
				// cancel the recurring task
				self.handshakeInitiationTask = nil
				return
			}
			do {
				try cc.accessContext { contextPtr in
					try withUnsafePointer(to:pubKey) { pubKeyPtr in
						// forge the authenticated message
						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:ipk, responderStaticPublicKey:pubKeyPtr, initiatorPeerIndex:upi)
						let authenticatedPayload = try payload.finalize(responderStaticPublicKey:pubKeyPtr)
						
						// install the resulting crypto keys in the self initiated key storage
						self.selfInitiatedKeys.installInitiation(context:contextPtr.pointee, now:currentTime, initiatorEphemeralPrivateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)
						
						// encode the initiation and send it on the socket
						let handshakeInitiationMessage:Message = .initiation(authenticatedPayload)
						var encodedLength = 0
						handshakeInitiationMessage.RAW_encode(count:&encodedLength)
						var encBuffer = wireguardHandler.takeUnretainedValue().encodeBuffer!
						encBuffer.clear(minimumCapacity:encodedLength)
						encBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:encodedLength) { (ptr:UnsafeMutableRawBufferPointer) -> Int in
							return ptr.baseAddress!.distance(to:handshakeInitiationMessage.RAW_encode(dest:ptr.baseAddress!.assumingMemoryBound(to:UInt8.self)))
						}
						contextPtr.pointee.writeAndFlush(wireguardHandler.takeUnretainedValue().wrapOutboundOut(AddressedEnvelope<ByteBuffer>(remoteAddress:SocketAddress(toEP), data:encBuffer)), promise:nil)
					}
				}
			} catch let error {
				// fire the error into the channel and cancel the handshake task
				cc.accessContext { contextPtr in
					contextPtr.pointee.fireErrorCaught(error)
				}
				self.handshakeInitiationTask = nil
			}
		}))
	}

	/// extracts a pending handshake initiation from memory so it can be processed and upgraded to a full session.
	internal func handshakeInitiationResponse(context:ChannelHandlerContext, now:NIODeadline, initiatorPeerIndex:PeerIndex) -> (initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? {
		return selfInitiatedKeys.claimInitiation(context: context, now: now, initiatorPeerIndex:initiatorPeerIndex)
	}
}

// MARK: Sessions
extension PeerInfo.Live {
	/// returns the session (and its rotational position) for the given peer index
	internal func session(forPeerM:PeerIndex) -> Rotating<Session>.Positioned? {
		// check the current position
		switch rotation.current {
			case .some(let session):
				guard session.geometry.m != forPeerM else {
					return .current(session)
				}
				fallthrough
			case .none:
				// current position does not match. check the previous position
				switch rotation.previous {
					case .some(let session):
						guard session.geometry.m != forPeerM else {
							return .previous(session)
						}
						fallthrough
					case .none:
						// previous position does not match. check the next position
						switch rotation.next {
							case .some(let session):
								guard session.geometry.m != forPeerM else {
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

// MARK: Transit Key Apply
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
		logger.info("transmit keys generated from peer initiated handshake")

		// add the new index to the active indicies
		let wgh = wireguardHandler.takeUnretainedValue()
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
		logger.info("transmit keys generated from self initiated handshake")

		// apply the rotation of the existing sessions with the new session
		let rotationResults = rotation.rotate(replacingNext:Session(geometry:element, nVar:SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), tVar:SendReceive<Result.Bytes32, Result.Bytes32>(selfInitiated:kdfResults), establishedDate:now))
		
		// automatically update the wireguard handler as needed
		let wgh = wireguardHandler.takeUnretainedValue()
		if let outgoingPrevious = rotationResults.previous {
			wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingPrevious.geometry.m)
		}
		if let outgoingNext = rotationResults.next {
			wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingNext.geometry.m)
		}
		wgh.automaticallyUpdatedVariables.activeSessionIndicies.add(indexM:element.m, publicKey:publicKey)

		// fire the handshake information to the channel
		context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(sessionStartDate:now, publicKey:publicKey))

		// flush any pending data
		while var (pendingPacket) = postHandshakePackets.dequeue() {
			logger.trace("flushing queued post-handshake packet", metadata:["public-key_remote":"\(publicKey)"])
			wgh.writeBytes(context:context, publicKey:publicKey, payload:&pendingPacket.data, promise:pendingPacket.promise)
		}
		
		// cancel the scheduled handshake initiation task
		handshakeInitiationTask = nil
	}
}

// MARK: Session Rotation
extension PeerInfo.Live {
	fileprivate borrowing func applyRotation(context:borrowing ChannelHandlerContext, now:NIODeadline) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.debug("applying rotation to active cryptokey set. next -> current -> previous.")
		context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(sessionStartDate:now, publicKey:publicKey))
		guard let outgoingID = rotation.rotate() else {
			return
		}
		wireguardHandler.takeUnretainedValue().automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingID.geometry.m)
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

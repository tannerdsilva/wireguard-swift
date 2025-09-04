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
		private var ep:Endpoint?
		internal var persistentKeepalive:TimeAmount?
		internal var handshakeInitiationTime:TAI64N? = nil

		// handshake initiation
		private var selfInitiatedKeys:CurrentSelfInitiatedInfo

		/// thrown when pending data could not be written because the handshake rekey attempt time was exceeded
		internal struct RekeyAttemptTimeExceeded:Swift.Error {}
		private var handshakeInitiationTask:(NIODeadline, RepeatedTask)? = nil {
			didSet {
				oldValue?.1.cancel()
				postHandshakePackets.clearAll(error:RekeyAttemptTimeExceeded())
			}
		}
		// packets that need to be sent after a handshake is complete
		private var postHandshakePackets = PendingPostHandshake()

		// cryptokey rotation
		private var rotation:Rotating<(NIODeadline, Session)>
		
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
			rotation = Rotating<(NIODeadline, Session)>()

			let um = Unmanaged.passUnretained(handler)
			wireguardHandler = um
			selfInitiatedKeys = CurrentSelfInitiatedInfo(responderStaticPublicKey:peerInfo.publicKey, handler:um)
		}
		
		internal func getSendVars(now:NIODeadline) -> (nSend:Counter, tSend:Result.Bytes32, geometry:HandshakeGeometry<PeerIndex>)? {
			guard let (_, currentGeometry) = rotation.current else {
				// no active handshakes
				return nil
			}
			// there is current geometry to evaluate. ensure this geometry 
			defer {
				rekeyAttemptTimeNow = now
			}
			return (nSend:currentGeometry.nVar.valueSend, tSend:currentGeometry.tVar.valueSend, geometry:currentGeometry.geometry)
		}

		internal func nSendUpdate(_ nSend:Counter, geometry:HandshakeGeometry<PeerIndex>) {
			guard var (startDate, currentSession) = rotation.current else {
				fatalError("no active handshakes")
			}
			currentSession.nVar.valueSend = nSend
			rotation.current = (startDate, currentSession)
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

		// set the rekey attempt timer to now if there is no existing timer
		if rekeyAttemptTimeNow == nil {
			rekeyAttemptTimeNow = now
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
	/// returns the session for the given peer index
	internal func session(forPeerM:PeerIndex) -> Rotating<Session>.Positioned? {
		// check the current position
		switch rotation.current {
			case .some(let (_, session)):
				guard session.geometry.m != forPeerM else {
					return .current(session)
				}
				fallthrough
			case .none:
				// current position does not match. check the previous position
				switch rotation.previous {
					case .some(let (_, session)):
						guard session.geometry.m != forPeerM else {
							return .previous(session)
						}
						fallthrough
					case .none:
						// previous position does not match. check the next position
						switch rotation.next {
							case .some(let (_, session)):
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
		guard let (_, outgoingIndexValue) = rotation.apply(next:(now, Session(geometry:element, nVar:WireguardHandler.SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), tVar:WireguardHandler.SendReceive<Result.Bytes32, Result.Bytes32>(peerInitiated:kdfResults)))) else {
			// no outgoing index value, return
			return
		}

		// clean up the outgoing index value
		wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingIndexValue.geometry.m)
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
		let rotationResults = rotation.rotate(replacingNext:(now, Session(geometry:element, nVar:WireguardHandler.SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), tVar:WireguardHandler.SendReceive<Result.Bytes32, Result.Bytes32>(selfInitiated:kdfResults))))
		
		// automatically update the wireguard handler as needed
		let wgh = wireguardHandler.takeUnretainedValue()
		if let (_, outgoingPrevious) = rotationResults.previous {
			wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingPrevious.geometry.m)
		}
		if let (_, outgoingNext) = rotationResults.next {
			wgh.automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingNext.geometry.m)
		}
		wgh.automaticallyUpdatedVariables.activeSessionIndicies.add(indexM:element.m, publicKey:publicKey)

		// fire the handshake information to the channel
		context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(publicKey:publicKey))

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
	internal borrowing func applyRotation(context:borrowing ChannelHandlerContext) -> HandshakeGeometry<PeerIndex>? {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.debug("applying rotation to active cryptokey set. next -> current -> previous.")
		context.fireUserInboundEventTriggered(WireguardHandler.WireguardHandshakeNotification(publicKey:publicKey))
		guard let (_, outgoingID) = rotation.rotate() else {
			return nil
		}
		wireguardHandler.takeUnretainedValue().automaticallyUpdatedVariables.activeSessionIndicies.removeIfPresent(indexM:outgoingID.geometry.m)
		return outgoingID.geometry
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

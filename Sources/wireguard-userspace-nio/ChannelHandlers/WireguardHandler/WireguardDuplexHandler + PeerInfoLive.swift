import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo.Live {
	private struct PendingPostHandshake {
		private var pendingWriteData:[(data:ByteBuffer, promise:EventLoopPromise<Void>?)] = []
		internal mutating func queue(data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			pendingWriteData.append((data:data, promise:promise))
		}
		internal mutating func dequeue() -> (data:ByteBuffer, promise:EventLoopPromise<Void>?)? {
			return pendingWriteData.isEmpty ? nil : pendingWriteData.removeFirst()
		}
	}

	private struct SendReceive<SendType, ReceiveType> {
		internal var valueSend:SendType
		internal var valueRecv:ReceiveType
		fileprivate init(valueSend vs:SendType, valueRecv vr:ReceiveType) {
			valueSend = vs
			valueRecv = vr
		}
		fileprivate init(peerInitiated inputTuple:(SendType, ReceiveType)) where SendType == ReceiveType {
			valueSend = inputTuple.1
			valueRecv = inputTuple.0
		}
		fileprivate init(selfInitiated inputTuple:(SendType, ReceiveType)) where SendType == ReceiveType {
			valueSend = inputTuple.0
			valueRecv = inputTuple.1
		}
	}

	/// primary mechanism for storing chaining data for initiations sent outbound.
	private struct SelfInitiated {
		private let responderStaticPublicKey:PublicKey
		private let wireguardHandler:Unmanaged<WireguardHandler>
		private var lastHandshakeEmissionTime:NIODeadline? = nil
		private var initiatorChainingData:(initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? = nil
		internal init(responderStaticPublicKey initiatorPub:PublicKey, handler:Unmanaged<WireguardHandler>) {
			wireguardHandler = handler
			responderStaticPublicKey = initiatorPub
		}
		fileprivate mutating func canProceedWithHandshakeEmission(context:borrowing ChannelHandlerContext, now:NIODeadline) -> Bool {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard lastHandshakeEmissionTime == nil || (lastHandshakeEmissionTime! + WireguardHandler.rekeyTimeout) < now else {
				return false
			}
			return true
		}
		fileprivate mutating func installInitiation(context:borrowing ChannelHandlerContext, now:NIODeadline, initiatorEphemeralPrivateKey ephemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			initiatorChainingData = (ephemeralPrivateKey, c, h, authenticatedPayload)
			lastHandshakeEmissionTime = now
			_ = wireguardHandler.takeUnretainedValue().activelyInitiatingIndicies.setActivelyInitiating(context:context, publicKey:responderStaticPublicKey, initiatorPeerIndex:authenticatedPayload.payload.initiatorPeerIndex)
		}
		fileprivate mutating func claimInitiation(context:borrowing ChannelHandlerContext, now:NIODeadline, initiatorPeerIndex:PeerIndex) -> (initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard initiatorPeerIndex == initiatorChainingData?.initiationPacket.payload.initiatorPeerIndex else {
				// the initiator peer index that invoked this remove event does not match the latest emitted packet
				return nil
			}
			guard (lastHandshakeEmissionTime! + WireguardHandler.rekeyTimeout) >= now else {
				// timeout exceeded, this handshake is no longer valid
				return nil
			}
			defer {
				initiatorChainingData = nil
			}
			guard wireguardHandler.takeUnretainedValue().activelyInitiatingIndicies.removeIfExists(context:context, publicKey:responderStaticPublicKey) == initiatorPeerIndex else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			return initiatorChainingData
		}
	}
}

extension PeerInfo {
	internal final class Live {
		private let log:Logger
		private let wireguardHandler:Unmanaged<WireguardHandler>

		// standard configuration stuff
		internal let publicKey:PublicKey
		private var ep:Endpoint?
		internal var persistentKeepalive:TimeAmount?
		internal var handshakeInitiationTime:TAI64N? = nil

		// handshake initiation
		private var selfInitiatedKeys:SelfInitiated
		private var handshakeInitiationTask:(NIODeadline, RepeatedTask)? = nil

		// cryptokey rotation
		private var rotation:Rotating<(NIODeadline, HandshakeGeometry<PeerIndex>)>

		// packets that need to be sent after a handshake is complete
		private var postHandshakePackets = PendingPostHandshake()

		private var rekeyAttemptTimeNow:NIODeadline? = nil
		private var nVars:[HandshakeGeometry<PeerIndex>:SendReceive<Counter, SlidingWindow<Counter>>] = [:]
		private var tVars:[HandshakeGeometry<PeerIndex>:SendReceive<Result.Bytes32, Result.Bytes32>] = [:]
		
		internal init(_ peerInfo:PeerInfo, handler:WireguardHandler, context:ChannelHandlerContext, logLevel:Logger.Level) {
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
			rotation = Rotating<(NIODeadline, HandshakeGeometry<PeerIndex>)>()

			let um = Unmanaged.passUnretained(handler)
			wireguardHandler = um
			selfInitiatedKeys = SelfInitiated(responderStaticPublicKey:peerInfo.publicKey, handler:um)
		}
		
		internal enum SendVarsResult {
			case currentKeys(nSend:Counter, tSend:Result.Bytes32, geometry:HandshakeGeometry<PeerIndex>)
			case noCurrentKeys(lastRekeyAttempt:NIODeadline?)
		}
		internal func getSendVars() -> (nSend:Counter, tSend:Result.Bytes32, geometry:HandshakeGeometry<PeerIndex>)? {
			guard let (_, currentGeometry) = rotation.current else {
				// no active handshakes
				return nil
			}
			defer {
				rekeyAttemptTimeNow = NIODeadline.now()
			}
			return (nSend:nVars[currentGeometry]!.valueSend, tSend:tVars[currentGeometry]!.valueSend, geometry:currentGeometry)
		}

		internal func nSendUpdate(_ nSend:Counter, geometry:HandshakeGeometry<PeerIndex>) {
			guard var currentNVar = nVars[geometry] else {
				fatalError("no nVar for geometry \(geometry) \(#file):\(#line)")
			}
			currentNVar.valueSend = nSend
			nVars[geometry] = currentNVar
		}
		
		internal borrowing func queuePostHandshake(context:ChannelHandlerContext, data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			postHandshakePackets.queue(data:data, promise:promise)
		}

		internal borrowing func dequeuePostHandshake(context:ChannelHandlerContext) -> (data:ByteBuffer, promise:EventLoopPromise<Void>?)? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			return postHandshakePackets.dequeue()
		}

		internal borrowing func getRecvVars(geometry:HandshakeGeometry<PeerIndex>) -> (nRecv:SlidingWindow<Counter>, tRecv:Result.Bytes32)? {
			guard let nRecv = nVars[geometry]?.valueRecv, let tRecv = tVars[geometry]?.valueRecv else {
				return nil
			}
			return (nRecv:nRecv, tRecv:tRecv)
		}
	}
}

// MARK: Handshake Initiation
extension PeerInfo.Live {
	/// called to determine if a handshake can be sent at this time
	internal func canProceedWithHandshakeEmission(context:ChannelHandlerContext, now:NIODeadline) -> Bool {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		return selfInitiatedKeys.canProceedWithHandshakeEmission(context:context, now:now)
	}

	internal func launchHandshakeTask(context:ChannelHandlerContext, now:NIODeadline, endpointOverride epOverride:Endpoint?, initiatorStaticPrivateKey:MemoryGuarded<PrivateKey>) throws {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let targetEndpoint:Endpoint
		if epOverride != nil {
			// use the value that came from OutboundIn. do not document this endpoint until it is discovered in the response to this initiation.
			targetEndpoint = epOverride!
		} else if ep != nil {
			// use the value that came from the peer list
			targetEndpoint = ep!
		} else {
			// fail because no endpoint is known. this is a user error so no need to `fireErrorCaught`.
			throw WireguardHandler.UnknownPeerEndpoint()
		}

		guard rekeyAttemptTimeNow == nil || (rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > now else {
			// a rekey attempt was made recently, do not send another handshake initiation
			log.debug("skipping handshake initiation emission due to recent rekey attempt")

			throw WireguardHandler.RekeyAttemptTooSoon()
		}

		handshakeInitiationTask = (now, context.eventLoop.scheduleRepeatedTask(initialDelay:.seconds(0), delay:WireguardHandler.rekeyTimeout, { [weak self, ipk = initiatorStaticPrivateKey, pubKey = publicKey, cc = ContextContainer(context:context), toEP = targetEndpoint, l = log] task in
			guard let self = self else { return }
			let currentTime = NIODeadline.now()
			guard self.rekeyAttemptTimeNow == nil || (self.rekeyAttemptTimeNow! + WireguardHandler.rekeyAttemptTime) > currentTime else {
				// a rekey attempt was made recently, do not send another handshake initiation
				l.debug("skipping handshake initiation emission due to recent rekey attempt")
				return
			}
			withUnsafePointer(to:pubKey) { pubKeyPtr in
				do {
					let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:ipk, responderStaticPublicKey:pubKeyPtr)
					try cc.accessContext { contextPtr in
						let authenticatedPayload = try payload.finalize(responderStaticPublicKey:pubKeyPtr)
						self.selfInitiatedKeys.installInitiation(context:contextPtr.pointee, now:currentTime, initiatorEphemeralPrivateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)
						wireguardHandler.takeUnretainedValue().writeMessage(.initiation(authenticatedPayload), to:toEP, context:contextPtr.pointee, promise:nil)
					}
				} catch let error {
					self.log.error("failed to emit handshake initiation: \(error)", metadata:["error":"\(error)"])
				}
			}
		}))
		try withUnsafePointer(to:publicKey) { responderStaticPublicKeyPtr in
			let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorStaticPrivateKey, responderStaticPublicKey:responderStaticPublicKeyPtr)
			let authenticatedPayload = try payload.finalize(responderStaticPublicKey:responderStaticPublicKeyPtr)
			selfInitiatedKeys.installInitiation(context:context, now:now, initiatorEphemeralPrivateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)
		}
	}
}

// MARK: Transit Key Apply
extension PeerInfo.Live {
	/// called when a peer initiated handshake is received and a response is going to be sent out. the provided c value pointer is used to derive the handshake keys.
	internal func applyPeerInitiated(_ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws -> HandshakeGeometry<PeerIndex>? {
		#if DEBUG
		guard case .peerInitiated(m:_, mp:_) = element else {
			fatalError("self initiated geometry used on peer initiated function. \(#file):\(#line)")
		}
		#endif
		nVars.updateValue(SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), forKey:element)
		let kdfResults = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)
		tVars.updateValue(SendReceive<Result.Bytes32, Result.Bytes32>(peerInitiated:kdfResults), forKey:element)
		log.info("transmit keys generated from peer initiated handshake", metadata:["lhs":"\(kdfResults.0)", "rhs":"\(kdfResults.1)"])
		guard let (_, outgoingIndexValue) = rotation.apply(next:(NIODeadline.now(), element)) else {
			// no outgoing index value, return
			return nil
		}
		// clean up the outgoing index value
		nVars.removeValue(forKey:outgoingIndexValue)
		tVars.removeValue(forKey:outgoingIndexValue)
		return outgoingIndexValue
	}

	/// called when a handshake response is received for a self initiated handshake.
	internal func applySelfInitiated(_ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws -> (previous:HandshakeGeometry<PeerIndex>?, next:HandshakeGeometry<PeerIndex>?) {
		#if DEBUG
		guard case .selfInitiated(m:_, mp:_) = element else {
			fatalError("peer initiated geometry used on self initiated function. \(#file):\(#line)")
		}
		#endif
		nVars.updateValue(SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), forKey:element)
		let kdfResults = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)
		tVars.updateValue(SendReceive<Result.Bytes32, Result.Bytes32>(selfInitiated:kdfResults), forKey:element)
		log.info("transmit keys generated from self initiated handshake", metadata:["lhs":"\(kdfResults.0)", "rhs":"\(kdfResults.1)"])
		let rotationResults = rotation.rotate(replacingNext:(NIODeadline.now(), element))
		if let (_, outgoingPrevious) = rotationResults.previous {
			nVars.removeValue(forKey:outgoingPrevious)
			tVars.removeValue(forKey:outgoingPrevious)
		}
		if let (_, outgoingNext) = rotationResults.next {
			nVars.removeValue(forKey:outgoingNext)
			tVars.removeValue(forKey:outgoingNext)
		}
		return (previous:rotationResults.previous?.1, next:rotationResults.next?.1)
	}
}

// MARK: Session Rotation
extension PeerInfo.Live {		
	internal borrowing func currentRotation() -> (NIODeadline, HandshakeGeometry<PeerIndex>)? {
		return rotation.current
	}
	internal borrowing func nextRotation() -> (NIODeadline, HandshakeGeometry<PeerIndex>)? {
		return rotation.next
	}
	internal borrowing func applyRotation() -> HandshakeGeometry<PeerIndex>? {
		log.debug("applying rotation to active cryptokey set. next -> current -> previous.")
		guard let (_, outgoingID) = rotation.rotate() else {
			return nil
		}
		tVars.removeValue(forKey:outgoingID)
		nVars.removeValue(forKey:outgoingID)
		return outgoingID
	}
}

// MARK: Endpoint
extension PeerInfo.Live {
	/// retrieve the previously known endpoint for the peer
	internal borrowing func endpoint() -> Endpoint? {
		return ep
	}

	/// journal the endpoint that the peer has been observed at
	internal borrowing func updateEndpoint(_ inputEndpoint:Endpoint) {
		guard ep != inputEndpoint else {
			return
		}
		ep = inputEndpoint
		log.info("peer roamed to new endpoint", metadata:["endpoint_remote":"\(inputEndpoint)"])
	}
}
import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo {
	fileprivate final class Live<LiveIndexType> where LiveIndexType:Hashable, LiveIndexType:Equatable {
		fileprivate let log:Logger
		fileprivate let publicKey:PublicKey
		private var ep:Endpoint?
		fileprivate var persistentKeepalive:TimeAmount?
		private var rotation:Rotating<LiveIndexType>
		fileprivate var handshakeInitiationTime:TAI64N? = nil
		
		private struct SendReceive<SendType, ReceiveType> {
			internal var nSend:SendType
			internal var nRecv:ReceiveType
		}
		
		private var nVars:[LiveIndexType:SendReceive<Counter, SlidingWindow<Counter>>] = [:]
		private var tVars:[LiveIndexType:SendReceive<Result.Bytes32, Result.Bytes32>] = [:]
		
		fileprivate init(_ peerInfo:PeerInfo, context:ChannelHandlerContext, logLevel:Logger.Level) {
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
			rotation = Rotating<LiveIndexType>()
			_ = context
		}
		fileprivate borrowing func endpoint() -> Endpoint? {
			return ep
		}
		/// journal the endpoint that the peer has been observed at
		fileprivate borrowing func updateEndpoint(_ inputEndpoint:Endpoint) {
			guard ep != inputEndpoint else {
				return
			}
			ep = inputEndpoint
			log.info("peer roamed to new endopint", metadata:["endpoint_remote":"\(inputEndpoint)"])
		}
		fileprivate func applyPeerInitiated(_ element:LiveIndexType) -> LiveIndexType? {
			log.info("rotation applied for peer initiated data")
			guard let outgoingIndexValue = rotation.apply(next:element) else {
				// no outgoing index value, return
				return nil
			}
			nVars.removeValue(forKey:outgoingIndexValue)
		}
		fileprivate func applySelfInitiated(_ element:LiveIndexType) -> LiveIndexType? {
			log.info("rotation applied for self initiated data")
			let rotationResults = rotation.rotate(replacingNext:element)
			if rotationResults.previous != nil {
				nVars.removeValue(forKey:rotationResults.previous!)
			}
			if rotationResults.next != nil {
				nVars.removeValue(forKey:rotationResults.next!)
			}
		}
	}
}

// tools
extension WireguardHandler {
	private struct PeerDeltaEngine {
		internal typealias PeerAdditionHandler = (PublicKey) -> Void
		internal typealias PeerRemovalHandler = (PublicKey) -> Void

		private let additionHandler:PeerAdditionHandler
		private let removalHandler:PeerRemovalHandler
		private var peers:[PublicKey:PeerInfo.Live<HandshakeGeometry<PeerIndex>>] {
			didSet {
				let keyDelta = Delta<PublicKey>(start:oldValue.keys, end:peers.keys)
				// handle the peers that were only at the start
				for removedPeer in keyDelta.exclusiveStart {
					removalHandler(removedPeer)
				}
				// handle the peers that were only at the end
				for newPeer in keyDelta.exclusiveEnd {
					additionHandler(newPeer)
				}
			}
		}
				
		internal init(context:ChannelHandlerContext, initiallyConfigured:[PeerInfo], additionHandler ahIn:@escaping PeerAdditionHandler, removalHandler rhIn:@escaping PeerRemovalHandler) {
			peers = [:]
			additionHandler = ahIn
			removalHandler = rhIn
			var buildPeers = [PublicKey:PeerInfo.Live<HandshakeGeometry<PeerIndex>>]()
			for peer in initiallyConfigured {
				buildPeers[peer.publicKey] = PeerInfo.Live<HandshakeGeometry<PeerIndex>>(peer, context:context, logLevel:.debug)
			}
			peers = buildPeers
		}
		
		internal mutating func setPeers(_ newPeers:[PeerInfo], context:ChannelHandlerContext) {
			var buildPeers = [PublicKey:PeerInfo.Live<HandshakeGeometry<PeerIndex>>]()
			for peer in newPeers {
				buildPeers[peer.publicKey] = PeerInfo.Live<HandshakeGeometry<PeerIndex>>(peer, context:context, logLevel:.debug)
			}
			peers = buildPeers
		}
		
		fileprivate borrowing func peerLookup(publicKey:PublicKey) -> PeerInfo.Live<HandshakeGeometry<PeerIndex>>? {
			return peers[publicKey]
		}
	}
	// i think this needs some work
	internal struct RekeyGate {
		private var pubRekeyDeadline:[PublicKey:NIODeadline] = [:]
		internal mutating func canRekey(publicKey clientPub:PublicKey, now:NIODeadline, delta:TimeAmount) -> Bool {
			// compute the rekey timeout threshold based on provided now and delta values
			let futureTime = now + delta
			// check if this public key already has a deadline value
			guard let hasDeadline = pubRekeyDeadline[clientPub] else {
				// no prior rekey timeout stored...rekey allowed.
				pubRekeyDeadline[clientPub] = futureTime
				return true
			}
			guard hasDeadline <= futureTime else {
				// the deadline is further in the future than `futureDate`....rekey not allowed.
				return false
			}
			pubRekeyDeadline[clientPub] = futureTime
			return true
		}
	}
}

internal final class WireguardHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (Endpoint, Message)
	internal typealias InboundOut = PacketTypeInbound
	internal typealias OutboundIn = PacketTypeOutbound
	internal typealias OutboundOut = (Endpoint, Message)
	
	internal static let rekeyTimeout = TimeAmount.seconds(5)
	internal static let rekeyAttemptTime = TimeAmount.seconds(90)
	
	private enum State {
		case initialized([PeerInfo])
		case channelEngaged
		case terminated
	}
	
	internal var secretCookieR:Result.Bytes8 = try! generateSecureRandomBytes(as:Result.Bytes8.self)
	
	/// logger that will be used to produce output for the work completed by this handler
	private let log:Logger
	private let privateKey:MemoryGuarded<PrivateKey>
	internal let precomputedCookieKey:RAW_xchachapoly.Key
	internal let isCongested:Atomic<Bool> = .init(false)
	
	// functionally self-managed
	private var peerDeltaEngine:PeerDeltaEngine!
	private var rekeyGate = RekeyGate()
	private var selfInitiatedIndexes = SelfInitiatedIndexes()
	
	// directly managed
	private var operatingState:State

	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, initialPeers:[PeerInfo], logLevel:Logger.Level) {
		privateKey = pkIn
		let publicKey = PublicKey(privateKey: privateKey)
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		buildLogger[metadataKey:"public-key_self"] = "\(publicKey)"
		log = buildLogger
		
		// pre-computing HASH(LABEL-COOKIE || Spub)
		var hasher = try! WGHasher<RAW_xchachapoly.Key>()
		try! hasher.update([UInt8]("cookie--".utf8))
		try! hasher.update(publicKey)
		precomputedCookieKey = try! hasher.finish()
		
		log.trace("instance initialized", metadata:["peer_count":"\(initialPeers.count)"])
		operatingState = .initialized(initialPeers)
	}
}

extension WireguardHandler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		switch operatingState {
			case .initialized(let initPeers):
				peerDeltaEngine = PeerDeltaEngine(context:context, initiallyConfigured:initPeers, additionHandler: { [weak self, l = log] _ in 
					// when peer is added
				}, removalHandler: { [weak self, l = log] _ in
					// when peer is removed
				})
				operatingState = .channelEngaged
			default:
				fatalError("this should never happen \(#file):\(#line)")
		}
		logger.trace("handler added to NIO pipeline.")
	}
	internal func handlerRemoved(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		logger.trace("handler removed from NIO pipeline.")
		operatingState = .terminated
	}
	internal func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		logger.trace("user inbound event triggered")
	}
}

// swift nio read handler function
extension WireguardHandler {
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		// handles handshake packets, else passes them down
		do {
			let (endpoint, payload) = unwrapInboundIn(data)
			logger[metadataKey:"endpoint_remote"] = "\(endpoint)"
			switch payload {
				case .initiation(let payload):
					/*
					peers role: initiator
					our role: responder
					=================
					Im = responder peer index
					Im' = initiator peer index
					*/
					if isCongested.load(ordering:.acquiring) == true {
						do {
							try payload.validateUnderLoadNoNIO(responderStaticPrivateKey:privateKey, R:secretCookieR, endpoint:endpoint)
						} catch Message.Initiation.Payload.Authenticated.Error.mac1Invalid {
							logger.error("received invalid handshake initiation packet. ignoring.")
							return
						} catch let error {
							// create and send the cookie
							let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
							context.writeAndFlush(wrapOutboundOut((endpoint, .cookie(cookie)))).whenSuccess { [logger = logger, e = endpoint] in
								logger.trace("cookie reply message sent to endpoint")
							}
							return
						}
					}
					
					let responderPeerIndex = try generateSecureRandomBytes(as:PeerIndex.self)
					var (c, h, initiatorStaticPublicKey, timestamp) = try payload.validate(responderStaticPrivateKey: privateKey)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:initiatorStaticPublicKey) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(initiatorStaticPublicKey)"])
						return
					}
					let geometry = HandshakeGeometry<PeerIndex>.peerInitiated(m:responderPeerIndex, mp:payload.payload.initiatorPeerIndex)
					if let initiationTime = livePeerInfo.handshakeInitiationTime {
						guard timestamp > initiationTime else {
							logger.notice("dropping packet due to timestamp value")
							return
						}
					}
					livePeerInfo.updateEndpoint(endpoint)
					livePeerInfo.handshakeInitiationTime = timestamp
					livePeerInfo.applyPeerInitiated(geometry)
					selfInitiatedIndexes.clear(publicKey:initiatorStaticPublicKey)
					let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
					let response = try Message.Response.Payload.forge(c:c, h:h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &initiatorStaticPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey, responderPeerIndex:responderPeerIndex)
					let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&initiatorStaticPublicKey)
					logger.debug("successfully validated handshake initiation", metadata:["index_initiator":"\(payload.payload.initiatorPeerIndex)", "index_responder":"\(responderPeerIndex)", "public-key_remote":"\(initiatorStaticPublicKey)"])
					context.writeAndFlush(wrapOutboundOut((endpoint, .response(authResponse)))).whenSuccess { [logger = logger] in
						logger.trace("handshake response sent successfully")
					}
					break;
				case .response(let payload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
					guard let chainingData = selfInitiatedIndexes.extract(indexM:payload.payload.initiatorIndex) else {
						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					let val = try payload.validate(c:chainingData.c, h:chainingData.h, initiatorStaticPrivateKey:privateKey, initiatorEphemeralPrivateKey:chainingData.privateKey, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
					let geometry = HandshakeGeometry<PeerIndex>.selfInitiated(m:payload.payload.initiatorIndex, mp:payload.payload.responderIndex)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:chainingData.peerPublicKey) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(chainingData.peerPublicKey)"])
						return
					}
					livePeerInfo.applySelfInitiated(geometry)
					logger.debug("successfully validated handshake response", metadata:["index_initiator":"\(payload.payload.initiatorIndex)", "index_responder":"\(payload.payload.responderIndex)", "public-key_remote":"\(chainingData.peerPublicKey)"])
					break;
				case .cookie(let cookiePayload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
					guard let chainingData = selfInitiatedIndexes.extract(indexM:cookiePayload.receiverIndex) else {
						logger.error("received cookie response for unknown peer index \(cookiePayload.receiverIndex) with no existing ephemeral private key")
						return
					}
//					guard let peerInfo = peerDeltaEngine[
					logger.debug("received cookie packet", metadata:["public-key_remote":"\(chainingData.peerPublicKey)"])
					withUnsafePointer(to:chainingData.peerPublicKey) { expectedPeerPublicKey in
						var phantomCookie:Message.Initiation.Payload.Authenticated
						do {
							phantomCookie = try chainingData.authenticatedPayload.payload.finalize(responderStaticPublicKey:expectedPeerPublicKey, cookie:cookiePayload)
//							selfInitiatedInfo.initiatorPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
						} catch {
//							logger.error("failed to validate cookie and create msgMac2")
//							return
						}
						let nioNow = NIODeadline.now()
						selfInitiatedIndexes.journal(context:context, indexM:cookiePayload.receiverIndex, publicKey:expectedPeerPublicKey.pointee, chainingData:(privateKey:chainingData.privateKey, c:chainingData.c, h:chainingData.h, authenticatedPayload:chainingData.authenticatedPayload)) { [weak self, ap = chainingData.authenticatedPayload, start = nioNow, c = ContextContainer(context:context), endpoint = endpoint] timer in
							// rekey attempt task.
							guard let self = self, NIODeadline.now() - start < Self.rekeyAttemptTime else {
								// recurring task should no longer be running
								timer.cancel()
								return
							}
							// write another initiation packet
							c.accessContext { contextPointer in
								contextPointer.pointee.writeAndFlush(self.wrapOutboundOut((endpoint, .initiation(ap))), promise:nil)
							}
						}
					}

					break;
				
				default:
					break;
			}
		} catch let error {
			logger.error("error processing handshake packet: \(error)")
			context.fireErrorCaught(error)
		}
	}
}

// swift nio write handler function
extension WireguardHandler {
	/// thrown when a handshake initiation is attempted on a peer with no documented endpoint
	internal struct UnknownPeerEndpoint:Swift.Error {}
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		let nioNow = NIODeadline.now()
		do {
			switch unwrapOutboundIn(data) {
				case let .handshakeInitiate(peerPublicKey, endpoint):
				
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index (not yet known, only initiator peer index is available)
					*/
					logger[metadataKey:"public-key_remote"] = "\(peerPublicKey)"
					
					// this probably needs to be improved
					guard rekeyGate.canRekey(publicKey:peerPublicKey, now:nioNow, delta:Self.rekeyTimeout) == true else {
						logger.notice("rekey gate rejected outbound handshake initiation")
						return
					}
					
					try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
						// endpoint logic
						let targetEndpoint:Endpoint
						if endpoint != nil {
							// use the value that came from OutboundIn. do not document this endpoint until it is discovered in the response to this initiation.
							targetEndpoint = endpoint!
						} else if let peerEndpoint = peerDeltaEngine.peerLookup(publicKey:expectedPeerPublicKey.pointee)?.endpoint() {
							// use the value that came from the peer list
							targetEndpoint = peerEndpoint
						} else {
							// fail because no endpoint is known. this is a user error so no need to `fireErrorCaught`.
							promise?.fail(UnknownPeerEndpoint())
							return
						}
						
						// forge
						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:privateKey, responderStaticPublicKey:expectedPeerPublicKey)
						let authenticatedPayload = try payload.finalize(responderStaticPublicKey:expectedPeerPublicKey)
						
						// document
						selfInitiatedIndexes.journal(context:context, indexM:payload.initiatorPeerIndex, publicKey:expectedPeerPublicKey.pointee, chainingData:(privateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)) { [weak self, ap = authenticatedPayload, start = nioNow, c = ContextContainer(context:context), endpoint = targetEndpoint] timer in
							// rekey attempt task.
							guard let self = self, NIODeadline.now() - start < Self.rekeyAttemptTime else {
								// recurring task should no longer be running
								timer.cancel()
								return
							}
							// write another initiation packet
							c.accessContext { contextPointer in
								contextPointer.pointee.writeAndFlush(self.wrapOutboundOut((endpoint, .initiation(ap))), promise:nil)
							}
						}
						logger.debug("successfully forged handshake initiation message", metadata:["endpoint_remote":"\(targetEndpoint)", "public-key_remote":"\(peerPublicKey)", "index_initiator":"\(payload.initiatorPeerIndex)"])
						context.writeAndFlush(wrapOutboundOut((targetEndpoint, .initiation(authenticatedPayload))), promise:nil)
					}
					break;
				case .encryptedTransit(let publicKey, let payload):
					guard let ep = peerDeltaEngine.peerLookup(publicKey:publicKey)?.endpoint() else {
						logger.error("unable to find valid endpoint for peer", metadata:["public-key_remote":"\(publicKey)"])
						promise?.fail(UnknownPeerEndpoint())
						return
					}
					context.writeAndFlush(wrapOutboundOut((ep, .data(payload))), promise:promise)
				default:
					break;
			}
		} catch let error {
			logger.error("error thrown while trying to write outbound data", metadata:["error":"\(error)"])
			context.fireErrorCaught(error)
			promise?.fail(error)
		}
	}
}
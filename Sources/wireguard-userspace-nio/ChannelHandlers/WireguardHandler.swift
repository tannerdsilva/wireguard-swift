import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

// tools
extension WireguardHandler {
	fileprivate final class LivePeerInfo {
		fileprivate let publicKey:PublicKey
		fileprivate var endpoint:Endpoint?
		fileprivate var persistentKeepalive:TimeAmount?
		fileprivate init(_ peerInfo:PeerInfo) {
			publicKey = peerInfo.publicKey
			endpoint = peerInfo.endpoint
			persistentKeepalive = peerInfo.internalKeepAlive
		}
	}
	internal struct PeerDeltaEngine {
		internal typealias PeerAdditionHandler = (PublicKey) -> Void
		internal typealias PeerRemovalHandler = (PublicKey) -> Void

		internal let additionHandler:PeerAdditionHandler
		internal let removalHandler:PeerRemovalHandler
		private var peers:[PublicKey:LivePeerInfo] {
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
				
		internal init(initiallyConfigured:[PeerInfo], additionHandler ahIn:@escaping PeerAdditionHandler, removalHandler rhIn:@escaping PeerRemovalHandler) {
			peers = [:]
			additionHandler = ahIn
			removalHandler = rhIn
			var buildPeers = [PublicKey:LivePeerInfo]()
			for peer in initiallyConfigured {
				buildPeers[peer.publicKey] = LivePeerInfo(peer)
			}
			peers = buildPeers
		}
		
		internal mutating func setPeers(_ newPeers:[PeerInfo]) {
			var buildPeers = [PublicKey:LivePeerInfo]()
			for peer in newPeers {
				buildPeers[peer.publicKey] = LivePeerInfo(peer)
			}
			peers = buildPeers
		}
		
		fileprivate borrowing func peerLookup(publicKey:PublicKey) -> LivePeerInfo? {
			return peers[publicKey]
		}
	}
	internal struct SelfInitiatedIndexes {
		private struct Keys {
			private var initiatorEphemeralPrivateKey:[PeerIndex:MemoryGuarded<PrivateKey>] = [:]
			private var initiatorChainingData:[PeerIndex:(c:Result.Bytes32, h:Result.Bytes32)] = [:]
			private var initiatorPackets:[PeerIndex:Message.Initiation.Payload.Authenticated] = [:]
			fileprivate mutating func install(index:PeerIndex, privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated) {
				initiatorEphemeralPrivateKey[index] = privateKey
				initiatorChainingData[index] = (c:c, h:h)
				initiatorPackets[index] = authenticatedPayload
			}
			fileprivate mutating func remove(index:PeerIndex) -> (privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated)? {
				guard	let chTuple = initiatorChainingData.removeValue(forKey:index),
						let ephiKey = initiatorEphemeralPrivateKey.removeValue(forKey:index),
						let authPacket = initiatorPackets.removeValue(forKey:index) else {
					return nil
				}
				return (privateKey:ephiKey, c:chTuple.c, h:chTuple.h, authenticatedPayload:authPacket)
			}
		}
		private var chainingKeys:Keys = Keys()

		private struct RecurringRekey {
			private var rekeyAttemptTasks:[PeerIndex:RepeatedTask] = [:]
			fileprivate mutating func startRecurringRekey(interval:TimeAmount, for peerIndex:PeerIndex, context:ChannelHandlerContext, _ task:@escaping(RepeatedTask) throws -> Void) {
				guard let oldRecurringTask = rekeyAttemptTasks.updateValue(context.eventLoop.scheduleRepeatedTask(initialDelay:interval, delay:interval, notifying:nil, task), forKey:peerIndex) else {
					return
				}
				oldRecurringTask.cancel()
			}
			fileprivate mutating func endRecurringRekey(for peerIndex:PeerIndex) {
				guard let hasExistingTask = rekeyAttemptTasks.removeValue(forKey:peerIndex) else {
					return
				}
				hasExistingTask.cancel()
			}
		}
		private var recurringRekeys = RecurringRekey()
		
		private var indexMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyIndexM:[PublicKey:PeerIndex] = [:]
		internal mutating func journal(context:ChannelHandlerContext, index:PeerIndex, publicKey:PublicKey, chainingData:(privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated), _ task:@escaping(RepeatedTask) throws -> Void) {
			defer {
				chainingKeys.install(index:index, privateKey:chainingData.privateKey, c:chainingData.c, h:chainingData.h, authenticatedPayload:chainingData.authenticatedPayload)
				recurringRekeys.startRecurringRekey(interval:WireguardHandler.rekeyTimeout, for:index, context:context, task)
			}
			guard let oldInitiationIndex = publicKeyIndexM.updateValue(index, forKey:publicKey) else {
				indexMPublicKey[index] = publicKey
				return
			}
			defer {
				_ = chainingKeys.remove(index:oldInitiationIndex)
				recurringRekeys.endRecurringRekey(for:oldInitiationIndex)
			}
			guard indexMPublicKey.removeValue(forKey:oldInitiationIndex) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			indexMPublicKey[index] = publicKey
		}
		
		internal mutating func extract(index:PeerIndex) -> (peerPublicKey:PublicKey, privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated)? {
			guard let extractedPublicKey = indexMPublicKey.removeValue(forKey:index) else {
				// index never existed
				return nil
			}
			guard publicKeyIndexM.removeValue(forKey:extractedPublicKey) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			recurringRekeys.endRecurringRekey(for:index)
			let extractedData = chainingKeys.remove(index:index)!
			return (peerPublicKey:extractedPublicKey, privateKey:extractedData.privateKey, c:extractedData.c, h:extractedData.h, authenticatedPayload:extractedData.authenticatedPayload)
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
	
	/// logger that will be used to produce output for the work completed by this handler
	private let log:Logger
	internal let privateKey:MemoryGuarded<PrivateKey>
	
	// self-managed
	private var peerDeltaEngine:PeerDeltaEngine!
	private var rekeyGate = RekeyGate()
	private var selfInitiatedIndexes = SelfInitiatedIndexes()

	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, logLevel:Logger.Level) {
		privateKey = pkIn
		let publicKey = PublicKey(privateKey: privateKey)
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		buildLogger[metadataKey:"public-key_self"] = "\(publicKey)"
		log = buildLogger
		log.trace("instance initialized")
	}
}

// swift nio read handler function
extension WireguardHandler {
	internal borrowing func channelRead(context:ChannelHandlerContext, data:NIOAny) {
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
					
					/*
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
					*/
					let responderPeerIndex = try! generateSecureRandomBytes(as:PeerIndex.self)
					var (c, h, initiatorStaticPublicKey, timestamp) = try payload.validate(responderStaticPrivateKey: privateKey)
					logger.debug("successfully validated handshake initiation packet", metadata:["index_initiator":"\(payload.payload.initiatorPeerIndex)", "index_responder":"\(responderPeerIndex)", "public-key_remote":"\(initiatorStaticPublicKey)"])

					let geometry = HandshakeGeometry<PeerIndex>.peerInitiated(m:responderPeerIndex, mp:payload.payload.initiatorPeerIndex)
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
						} else if let peerEndpoint = peerDeltaEngine.peerLookup(publicKey:expectedPeerPublicKey.pointee)?.endpoint {
							// use the value that came from the peer list
							targetEndpoint = peerEndpoint
						} else {
							// fail because no endpoint is known. this is a user error so no need to `fireErrorCaught`.
							promise?.fail(UnknownPeerEndpoint())
							return
						}

						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:privateKey, responderStaticPublicKey:expectedPeerPublicKey)
						let authenticatedPayload = try payload.finalize(responderStaticPublicKey:expectedPeerPublicKey)
						selfInitiatedIndexes.journal(context:context, index:payload.initiatorPeerIndex, publicKey:expectedPeerPublicKey.pointee, chainingData:(privateKey:ephiPrivateKey, c:c, h:h, authenticatedPayload:authenticatedPayload)) { [weak self, ap = authenticatedPayload, start = nioNow, c = ContextContainer(context:context), endpoint = targetEndpoint] timer in
							guard let self = self, NIODeadline.now() - start < Self.rekeyAttemptTime else {
								timer.cancel()
								return
							}
							c.accessContext { contextPointer in
								contextPointer.pointee.writeAndFlush(self.wrapOutboundOut((endpoint, .initiation(ap))), promise:nil)
							}
						}
						logger.debug("successfully forged handshake initiation message", metadata:["endpoint_remote":"\(targetEndpoint)", "public-key_remote":"\(peerPublicKey)", "index_initiator":"\(payload.initiatorPeerIndex)"])
						context.writeAndFlush(wrapOutboundOut((targetEndpoint, .initiation(authenticatedPayload))), promise:nil)
					}
					break;
				case .encryptedTransit(let publicKey, let payload):
					guard let ep = peerDeltaEngine.peerLookup(publicKey:publicKey)?.endpoint else {
						logger.error("unable to find valid endpoint for peer", metadata:["public-key_remote":"\(publicKey)"])
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
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
	internal struct PeerDeltaEngine {
		internal typealias PeerAdditionHandler = (PublicKey) -> Void
		internal typealias PeerRemovalHandler = (PublicKey) -> Void
		private var peers:[PublicKey:PeerInfo] {
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
		
		internal let additionHandler:PeerAdditionHandler
		internal let removalHandler:PeerRemovalHandler
		
		internal init(initiallyConfigured:[PeerInfo], additionHandler ahIn:@escaping PeerAdditionHandler, removalHandler rhIn:@escaping PeerRemovalHandler) {
			peers = [:]
			additionHandler = ahIn
			removalHandler = rhIn
			var buildPeers = [PublicKey:PeerInfo]()
			for peer in initiallyConfigured {
				buildPeers[peer.publicKey] = peer
			}
			peers = buildPeers
		}
		
		internal mutating func setPeers(_ newPeers:[PeerInfo]) {
			var buildPeers = [PublicKey:PeerInfo]()
			for peer in newPeers {
				buildPeers[peer.publicKey] = peer
			}
			peers = buildPeers
		}
	}

	internal struct SelfInitiatedIndexes {
		private var indexMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyIndexM:[PublicKey:PeerIndex] = [:]
		internal mutating func journal(index:PeerIndex, publicKey:PublicKey) {
			guard let oldInitiationIndex = publicKeyIndexM.updateValue(index, forKey:publicKey) else {
				indexMPublicKey[index] = publicKey
				return
			}
			guard indexMPublicKey.removeValue(forKey:oldInitiationIndex) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			indexMPublicKey[index] = publicKey
		}
	}
	internal struct RekeyGate {
		private var pubRekeyDeadline:[PublicKey:NIODeadline] = [:]
		internal mutating func canRekey(publicKey clientPub:PublicKey, now:NIODeadline, delta:TimeAmount) -> Bool {
			// check if this public key already has a deadline value
			guard let hasDeadline = pubRekeyDeadline[clientPub] else {
				// no prior rekey timeout stored...rekey allowed.
				return true
			}
			// compute the rekey timeout threshold based on provided now and delta values
			let futureTime = now + delta
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
	
	/// logger that will be used to produce output for the work completed by this handler
	private let log:Logger
	internal let privateKey:MemoryGuarded<PrivateKey>
	
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


extension WireguardHandler {
	internal borrowing func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
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
					
					guard rekeyGate.canRekey(publicKey:peerPublicKey, now:nioNow, delta:.seconds(5)) == true else {
						logger.notice("rekey gate rejected outbound handshake initiation")
						return
					}
					
					try withUnsafePointer(to:peerPublicKey) { expectedPeerPublicKey in
						let (c, h, ephiPrivateKey, payload) = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:privateKey, responderStaticPublicKey:expectedPeerPublicKey)
						selfInitiatedIndexes.journal(index:payload.initiatorPeerIndex, publicKey:expectedPeerPublicKey.pointee)
					}
					break;
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
import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import bedrock

extension WireguardHandler {
	/// used to store and index peers against their corresponding public keys. also enables easy handler functions to react to peer additions and removals.
	internal struct PeerDeltaEngine:Sendable {
		/// the type of handler that is used for peer additions
		internal typealias PeerAdditionHandler = @Sendable (PublicKey) -> Void
		/// the type of handler that is used for peer removals
		internal typealias PeerRemovalHandler = @Sendable (PublicKey, PeerInfo.Live) -> Void

		/// the logger that will be used to produce output for the work completed by this engine
		private let log:Logger

		/// the addition handler that will be fired on peer additions
		private let additionHandler:PeerAdditionHandler
		/// the removal handler that will be fired on peer removals
		private let removalHandler:PeerRemovalHandler

		/// the current set of peers being tracked
		private var peers:[PublicKey:PeerInfo.Live] {
			didSet {
				let keyDelta = Delta<PublicKey>(start:oldValue.keys, end:peers.keys)
				// handle the peers that were only at the start
				for removedPeer in keyDelta.exclusiveStart {
					log.trace("removed peer from delta engine.", metadata:["public-key_removed":"\(removedPeer)"])
					removalHandler(removedPeer, oldValue[removedPeer]!)
				}
				// handle the peers that were only at the end
				for newPeer in keyDelta.exclusiveEnd {
					log.trace("added peer to delta engine.", metadata:["public-key_added":"\(newPeer)"])
					additionHandler(newPeer)
				}
			}
		}
		
		/// initialize a new peer delta engine with the given initial peers and handlers.
		internal init<S>(context:ChannelHandlerContext, initiallyConfigured:S, handler:WireguardHandler, logLevel:Logger.Level, additionHandler ahIn:@escaping PeerAdditionHandler, removalHandler rhIn:@escaping PeerRemovalHandler) where S:Sequence, S.Element == PeerInfo {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			log = buildLogger
			peers = [:]
			additionHandler = ahIn
			removalHandler = rhIn
			var buildPeers = [PublicKey:PeerInfo.Live]()
			for peer in initiallyConfigured {
				buildPeers[peer.publicKey] = PeerInfo.Live(peer, handler:handler, context:context, logLevel:logLevel)
			}
			peers = buildPeers
		}
		
		/// set the current set of peers that should be considered 'active' and 'enabled' for networking with this endpoint.
		internal mutating func setPeers<S>(context:borrowing ChannelHandlerContext, _ newPeers:consuming S, handler:WireguardHandler) where S:Sequence, S.Element == PeerInfo {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			var buildPeers = [PublicKey:PeerInfo.Live]()
			for peer in newPeers {
				buildPeers[peer.publicKey] = PeerInfo.Live(peer, handler:handler, context:context, logLevel:log.logLevel)
			}
			peers = buildPeers
		}
		
		/// lookup a peers instance by its public key.
		internal borrowing func peerLookup(publicKey:PublicKey) -> PeerInfo.Live? {
			return peers[publicKey]
		}
	}
}

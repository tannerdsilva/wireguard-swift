import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler.AutomaticallyUpdated {

	/// used to track the association of Im (peer index m) and the public keys they associate with
	internal struct MPeerIndex:Sendable {
		/// the logger that will be used to produce output for the work completed by this structure
		private let log:Logger
		/// the dictionary that maps a given m peer index with the corresponding public key of the remote peer
		private var peerMPublicKey:[PeerIndex:PublicKey] = [:]
		/// the dictionary that maps a given public key with the corresponding m peer indices
		private var publicKeyPeerM:[PublicKey:Set<PeerIndex>] = [:]

		/// initialize a new mpeer index structure.
		internal init(logLevel:consuming Logger.Level) {
			var logger = Logger(label:"\(String(describing:Self.self))")
			logger.logLevel = logLevel
			log = logger
		}

		/// associate a peer index m with a public key. if the peer index m already exists, it must be associated with the same public key that was passed as an argument.
		/// - parameter index: the peer index m to associate
		/// - parameter publicKey: the public key to associate with the peer index m
		internal mutating func add(indexM index:PeerIndex, publicKey:PublicKey) {
			let existingValue = peerMPublicKey.updateValue(publicKey, forKey:index)
			guard existingValue == nil || existingValue! == publicKey else {
				log.critical("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			if var hasExistingPISet = publicKeyPeerM[publicKey] {
				hasExistingPISet.update(with:index)
				publicKeyPeerM[publicKey] = hasExistingPISet
			} else {
				publicKeyPeerM[publicKey] = [index]
			}
			#if DEBUG
			log.trace("added peer index m association.", metadata:["public-key_remote":"\(publicKey)", "peer-index-m":"\(index)"])
			#endif
		}

		/// remove the association of a peer index m with a public key, if it exists. if the peer index m does not exist, this is a no-op.
		/// - parameter index: the peer index m to remove
		internal mutating func removeIfPresent(indexM index:PeerIndex) {
			guard let hasExistingPublicKey = peerMPublicKey.removeValue(forKey:index) else {
				return
			}
			guard var hasExistingPISet = publicKeyPeerM[hasExistingPublicKey] else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			guard hasExistingPISet.count > 0 else {
				publicKeyPeerM.removeValue(forKey:hasExistingPublicKey)
				return
			}
			guard hasExistingPISet.remove(index) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			_ = publicKeyPeerM.updateValue(hasExistingPISet, forKey:hasExistingPublicKey)
			#if DEBUG
			log.trace("removed peer index m association.", metadata:["public-key_remote":"\(hasExistingPublicKey)", "peer-index-m":"\(index)"])
			#endif
		}

		/// seek for the public key that is associated with a given peer index m, if it exists.
		internal borrowing func seek(indexM index:borrowing PeerIndex) -> PublicKey? {
			return peerMPublicKey[index]
		}
	}
}

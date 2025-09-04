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
	internal struct MPeerIndex {
		private let log:Logger
		private var peerMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyPeerM:[PublicKey:Set<PeerIndex>] = [:]

		/// initialize a new mpeer index structure.
		internal init(logLevel:Logger.Level) {
			var logger = Logger(label: "\(String(describing:Self.self))")
			logger.logLevel = logLevel
			log = logger
		}

		/// associate a peer index m with a public key. if the peer index m already exists, it must be associated with the same public key that was passed as an argument.
		internal mutating func add(indexM index:PeerIndex, publicKey:PublicKey) {
			// if this peer index already exists, it must not exist 
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
		}
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
		}
		internal borrowing func seek(indexM index:PeerIndex) -> PublicKey? {
			return peerMPublicKey[index]
		}
	}
}
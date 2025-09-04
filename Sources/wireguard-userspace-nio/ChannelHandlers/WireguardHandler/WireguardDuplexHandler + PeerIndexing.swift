import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	internal struct MPeerIndex {
		private let log:Logger
		private var peerMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyPeerM:[PublicKey:Set<PeerIndex>] = [:]
		internal init(logLevel:Logger.Level) {
			var logger = Logger(label: "\(String(describing:Self.self))")
			logger.logLevel = logLevel
			log = logger
		}

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
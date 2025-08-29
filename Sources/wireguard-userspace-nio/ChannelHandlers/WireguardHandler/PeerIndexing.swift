import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	fileprivate struct PeerIndexKeyMapper {
		private var indexPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyIndex:[PublicKey:Set<PeerIndex>] = [:]
		fileprivate mutating func add(index:PeerIndex, publicKey:PublicKey) {
			guard indexPublicKey.updateValue(publicKey, forKey:index) == nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			if var hasExistingPISet = publicKeyIndex[publicKey] {
				guard hasExistingPISet.update(with:index) == nil else {
					fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
				}
				publicKeyIndex[publicKey] = hasExistingPISet
			} else {
				publicKeyIndex[publicKey] = [index]
			}
		}
		fileprivate mutating func remove(index:PeerIndex) {
			guard let hasExistingPublicKey = indexPublicKey.removeValue(forKey:index) else {
				return
			}
			guard var hasExistingPISet = publicKeyIndex[hasExistingPublicKey] else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			guard hasExistingPISet.remove(index) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			guard hasExistingPISet.count > 0 else {
				publicKeyIndex.removeValue(forKey:hasExistingPublicKey)
				return
			}
			_ = publicKeyIndex.updateValue(hasExistingPISet, forKey:hasExistingPublicKey)
		}
		@discardableResult fileprivate mutating func remove(publicKey:PublicKey) -> Set<PeerIndex> {
			guard let hasExistingIDsInstalled = publicKeyIndex.removeValue(forKey:publicKey) else {
				// there is no existing value
				return []
			}
			for curItem in hasExistingIDsInstalled {
				guard indexPublicKey.removeValue(forKey:curItem) != nil else {
					fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
				}
			}
			return hasExistingIDsInstalled
		}
	}
}

extension WireguardHandler {
	internal struct DualPeerIndex {
		private var peerM = PeerIndexKeyMapper()
		private var peerMP = PeerIndexKeyMapper()
		internal mutating func add(geometry:HandshakeGeometry<PeerIndex>, publicKey:PublicKey) {
			peerM.add(index:geometry.m, publicKey:publicKey)
			peerMP.add(index:geometry.mp, publicKey:publicKey)
		}
		internal mutating func remove(index:PeerIndex) {
			peerM.remove(index:index)
			peerMP.remove(index:index)
		}
		@discardableResult fileprivate mutating func remove(publicKey:PublicKey) -> (m:Set<PeerIndex>?, mp:Set<PeerIndex>?) {
			return (m:peerM.remove(publicKey:publicKey), mp:peerMP.remove(publicKey:publicKey))
		}
	}
}
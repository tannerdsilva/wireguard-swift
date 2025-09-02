import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	/// maps a given peer index to a corresponding public key. this mapper was updated to allow associations with the complete HandshakeGeometry<PeerIndex> value.
	fileprivate struct PeerIndexKeyMapper {
		/// maps an index value to a corresponding (public key, handshakegeometry) tuple
		private var indexPublicKey:[PeerIndex:(PublicKey, HandshakeGeometry<PeerIndex>)] = [:]
		/// maps a public key to a set of associated index values
		private var publicKeyIndex:[PublicKey:Set<PeerIndex>] = [:]

		/// install a new handshake geometry and public key into the mapper
		fileprivate mutating func add(index:PeerIndex, associated geometry:HandshakeGeometry<PeerIndex>, publicKey:PublicKey) {
			guard indexPublicKey.updateValue((publicKey, geometry), forKey:index) == nil else {
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

		/// remove a peer index and its associated public key and handshake geometry. if this is the last peer index to associate with the public key, the public key will be removed from the mapper.
		fileprivate mutating func remove(index:PeerIndex) {
			guard let (hasExistingPublicKey, _) = indexPublicKey.removeValue(forKey:index) else {
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

		/// remove a public key and all associated peer indicies from the mapper.
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

		/// identify the corresponding public key and handshake geometry for a given peer index.
		fileprivate borrowing func seek(_ pi:PeerIndex) -> (PublicKey, HandshakeGeometry<PeerIndex>)? {
			return indexPublicKey[pi]
		}
	}
}

extension WireguardHandler {
	/// the dual peer index helps correlate a single peer index with a complete HandshakeGeometry<PeerIndex> value.
	internal struct DualPeerIndex {
		private var peerM = PeerIndexKeyMapper()
		private var peerMP = PeerIndexKeyMapper()
		internal mutating func add(geometry:HandshakeGeometry<PeerIndex>, publicKey:PublicKey) {
			peerM.add(index:geometry.m, associated:geometry, publicKey:publicKey)
			peerMP.add(index:geometry.mp, associated:geometry, publicKey:publicKey)
		}
		internal mutating func remove(geometry:HandshakeGeometry<PeerIndex>) {
			peerM.remove(index:geometry.m)
			peerMP.remove(index:geometry.mp)
		}
		@discardableResult internal mutating func remove(publicKey:PublicKey) -> (m:Set<PeerIndex>?, mp:Set<PeerIndex>?) {
			return (m:peerM.remove(publicKey:publicKey), mp:peerMP.remove(publicKey:publicKey))
		}
		internal borrowing func seek(peerM peerMIndex:PeerIndex) -> (PublicKey, HandshakeGeometry<PeerIndex>)? {
			return peerM.seek(peerMIndex)
		}
	}
}
import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	private struct PeerIndexMMapper {
		private var indexMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyIndexM:[PublicKey:Set<PeerIndex>] = [:]
		internal mutating func add(geometry:HandshakeGeometry<PeerIndex>, publicKey:PublicKey) {
			let index = geometry.m
			guard indexMPublicKey.updateValue(publicKey, forKey:index) == nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			if var hasExistingPISet = publicKeyIndexM[publicKey] {
				guard hasExistingPISet.update(with:index) == nil else {
					fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
				}
				publicKeyIndexM[publicKey] = hasExistingPISet
			} else {
				publicKeyIndexM[publicKey] = [index]
			}
		}
		internal mutating func remove(geometry:HandshakeGeometry<PeerIndex>) {
			let index = geometry.m
			guard let hasExistingPublicKey = indexMPublicKey.removeValue(forKey:index) else {
				return
			}
			guard var hasExistingPISet = publicKeyIndexM[hasExistingPublicKey] else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			guard hasExistingPISet.remove(index) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			guard hasExistingPISet.count > 0 else {
				publicKeyIndexM.removeValue(forKey:hasExistingPublicKey)
				return
			}
			_ = publicKeyIndexM.updateValue(hasExistingPISet, forKey:hasExistingPublicKey)
		}
	}
}
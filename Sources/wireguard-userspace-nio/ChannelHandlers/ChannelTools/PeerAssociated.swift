import RAW_dh25519

/// Associates a type instance with a peer public key.
public struct PeerAssociated<AssociatedType:Sendable & Hashable>:Sendable {
	/// The public key of the peer that this instance is associated with.
	internal let publicKey:PublicKey
	/// The value that is associated with the peer public key.
	internal var associatedValue:AssociatedType
	/// Creates a new instance of `PeerAssociated`.
	/// - Parameters:
	///   - publicKey: The public key of the peer that this instance is associated with.
	///   - associatedValue: The value that is associated with the peer public key.
	internal init(publicKey:PublicKey, associatedValue:AssociatedType) {
		self.publicKey = publicKey
		self.associatedValue = associatedValue
	}
}

extension PeerAssociated:LenghExpressibleExchangeType where AssociatedType:LenghExpressibleExchangeType {
	internal var bytesOnWire:Int {
		return associatedValue.bytesOnWire
	}
}

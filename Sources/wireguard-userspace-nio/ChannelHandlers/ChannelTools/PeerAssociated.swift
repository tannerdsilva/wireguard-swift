import RAW_dh25519

/// used to associate a type instance with a peer public key.
internal struct PeerAssociated<AssociatedType:Sendable & Hashable>:Sendable {
	/// the public key of the peer that this instance is associated with.
	internal let publicKey:PublicKey
	/// the value that is associated with the peer public key.
	internal var associatedValue:AssociatedType
	/// creates a new instance of PeerAssociated
	///	- parameters:
	///		- publicKey: the public key of the peer that this instance is associated with
	///		- associatedValue: the value that is associated with the peer public key
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
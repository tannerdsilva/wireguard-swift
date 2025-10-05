import RAW_dh25519

internal struct PeerAssociated<AssociatedType:Sendable & Hashable>:Sendable {
	internal let publicKey:PublicKey
	internal var associatedValue:AssociatedType
	internal init(publicKey:PublicKey, associatedValue:AssociatedType) {
		self.publicKey = publicKey
		self.associatedValue = associatedValue
	}
	internal init(_ tuple:(PublicKey, AssociatedType)) {
		self.publicKey = tuple.0
		self.associatedValue = tuple.1
	}
}

extension PeerAssociated:LenghExpressibleExchangeType where AssociatedType:LenghExpressibleExchangeType {
	internal var bytesOnWire:Int {
		return associatedValue.bytesOnWire
	}
}
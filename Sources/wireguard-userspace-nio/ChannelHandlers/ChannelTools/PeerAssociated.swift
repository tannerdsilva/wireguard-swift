import RAW_dh25519

internal struct PeerAssociated<AssociatedType:Sendable & Hashable>:Sendable {
	public let publicKey:PublicKey
	public var associatedValue:AssociatedType
	public init(publicKey: PublicKey, associatedValue: AssociatedType) {
		self.publicKey = publicKey
		self.associatedValue = associatedValue
	}
}
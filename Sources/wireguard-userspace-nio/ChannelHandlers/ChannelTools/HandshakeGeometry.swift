/// used to express the layout of cryptography that enables a tunnel with any given peer.
internal enum HandshakeGeometry<AugmentedType>:Hashable, Equatable where AugmentedType:Hashable, AugmentedType:Equatable {
	/// describes a scenario where the encrypted tunnel handshake is initiated by "self"
	/// - in this scenario:
	///		- m = initiator peer index
	///		- m' = responder peer index
	case selfInitiated(m:AugmentedType, mp:AugmentedType)
	
	/// describes a scenario where the encrypted tunnel handshake is initiated by the remote peer to "self"
	/// - in this scenario:
	///		- m = responder peer index
	///		- m' = initiator peer index
	case peerInitiated(m:AugmentedType, mp:AugmentedType)
	
	/// access the m value
	internal var m:AugmentedType {
		switch self {
			case .selfInitiated(m:let m, mp:let mp):
			return m
			case .peerInitiated(m:let m, mp:let mp):
			return m
		}
	}
	
	/// access the m prime value
	internal var mp:AugmentedType {
		switch self {
			case .selfInitiated(m:let m, mp:let mp):
			return mp
			case .peerInitiated(m:let m, mp:let mp):
			return mp
		}
	}
	
	/// access the value of self, also known as `m`
	internal var selfValue:AugmentedType {
		switch self {
			case .selfInitiated(m:let m, mp:let mp):
			return m
			case .peerInitiated(m:let m, mp:let mp):
			return m
		}
	}
	
	/// access the value of the remote peer, also known as `mp`
	internal var peerValue:AugmentedType {
		switch self {
			case .selfInitiated(m:let m, mp:let mp):
			return mp
			case .peerInitiated(m:let m, mp:let mp):
			return mp
		}
	}
}

extension HandshakeGeometry:CustomDebugStringConvertible where AugmentedType:CustomDebugStringConvertible {
	internal var debugDescription:String {
		var startingString = "\(String(describing:Self.self))"
		
		return startingString
	}
}
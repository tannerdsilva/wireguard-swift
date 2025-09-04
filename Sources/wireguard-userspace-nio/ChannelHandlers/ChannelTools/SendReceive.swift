/// a general and "loosely defined" struct that combines two values that correspond with the send/receive pattern.
internal struct SendReceive<SendType, ReceiveType> {
	/// the value that corresponds with sending
	internal var valueSend:SendType
	/// the value that corresponds with receiving
	internal var valueRecv:ReceiveType

	/// initializer for the send/receive values
	internal init(valueSend vs:SendType, valueRecv vr:ReceiveType) {
		valueSend = vs
		valueRecv = vr
	}
}

extension SendReceive where SendType == ReceiveType {
	/// direct kdf initializer for peer initiated cryptography
	internal init(peerInitiated inputTuple:(SendType, ReceiveType)) {
		valueSend = inputTuple.1
		valueRecv = inputTuple.0
	}
	/// direct kdf initializer for self initiated cryptography
	internal init(selfInitiated inputTuple:(SendType, ReceiveType)) {
		valueSend = inputTuple.0
		valueRecv = inputTuple.1
	}
}
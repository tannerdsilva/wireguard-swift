import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo.Live {
	/// represents a wireguard tunnel connection with a unique set of transit keys.
	internal struct Session {
		/// the handshake geometry that was used to initiate the session
		internal let geometry:HandshakeGeometry<PeerIndex>
		/// the n variable that is used for the session's send/receive counters and sliding windows.
		internal var nVar:WireguardHandler.SendReceive<Counter, SlidingWindow<Counter>>
		/// the t variable that is used for the session's transmit/receive keys.
		internal var tVar:WireguardHandler.SendReceive<Result.Bytes32, Result.Bytes32>
		/// as defined by the wireguard whitepaper, this is the date that the handshake session was established (the moment the transit keys were computed)
		internal var establishedDate:NIODeadline
	}
}

extension WireguardHandler {
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
		internal init(peerInitiated inputTuple:(SendType, ReceiveType)) where SendType == ReceiveType {
			valueSend = inputTuple.1
			valueRecv = inputTuple.0
		}
		internal init(selfInitiated inputTuple:(SendType, ReceiveType)) where SendType == ReceiveType {
			valueSend = inputTuple.0
			valueRecv = inputTuple.1
		}
	}
}
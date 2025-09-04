import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo.Live {
	internal struct Session {
		internal let geometry:HandshakeGeometry<PeerIndex>
		internal var nVar:WireguardHandler.SendReceive<Counter, SlidingWindow<Counter>>
		internal var tVar:WireguardHandler.SendReceive<Result.Bytes32, Result.Bytes32>
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
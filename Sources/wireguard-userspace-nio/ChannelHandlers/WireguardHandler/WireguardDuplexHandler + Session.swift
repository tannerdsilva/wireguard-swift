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
		internal var nVar:SendReceive<Counter, SlidingWindow<Counter>>
		/// the t variable that is used for the session's transmit/receive keys.
		internal var tVar:SendReceive<Result.Bytes32, Result.Bytes32>
		/// as defined by the wireguard whitepaper, this is the date that the handshake session was established (the moment the transit keys were computed)
		internal let establishedDate:NIODeadline
	}
}
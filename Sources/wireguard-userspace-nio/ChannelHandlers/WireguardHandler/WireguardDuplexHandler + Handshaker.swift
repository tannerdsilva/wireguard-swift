import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	private struct HandshakeGate {
		internal enum HandshakeInvokeReason {
			case firstHandshake
			case proactiveRekey(forOutgoingGeometry:HandshakeGeometry<PeerIndex>)
		}
		private var reason:HandshakeInvokeReason = .firstHandshake
		private var lastHandshakeTime:NIODeadline? = nil
	}
}
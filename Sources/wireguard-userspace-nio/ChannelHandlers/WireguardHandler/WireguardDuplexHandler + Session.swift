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
	internal struct Session:Sendable {
		/// the handshake geometry that was used to initiate the session
		internal let geometry:HandshakeGeometry<PeerIndex>
		/// the n variable that is used for the session's send/receive counters and sliding windows.
		internal var nVar:SendReceive<Counter, SlidingWindow<Counter>>
		/// the t variable that is used for the session's transmit/receive keys.
		internal var tVar:SendReceive<Result.Bytes32, Result.Bytes32>
		/// as defined by the wireguard whitepaper, this is the date that the handshake session was established (the moment the transit keys were computed)
		internal let establishedDate:NIODeadline

		/// zeroes the transport (transit) keys held by this session out of memory. per the whitepaper
		/// (sections 5.4.5 and 7.4), ephemeral session keys and intermediate cryptographic state must be
		/// zeroed once the session is discarded ("the previous-previous one is then discarded and its
		/// memory is zeroed"). `secureZeroBytes` is used so the write is not optimized away as a dead store.
		internal mutating func zeroOut() {
			do {
				try tVar.valueSend.RAW_access_staticbuff_mutating { ptr in
					try secureZeroBytes(ptr, count:MemoryLayout<Result.Bytes32.RAW_staticbuff_storetype>.size)
				}
			} catch {
				// the wipe could not be verified; fall back to a best-effort plain zeroing.
				tVar.valueSend.RAW_access_staticbuff_mutating { ptr in
					ptr.initializeMemory(as:UInt8.self, repeating:0, count:MemoryLayout<Result.Bytes32.RAW_staticbuff_storetype>.size)
				}
			}
			do {
				try tVar.valueRecv.RAW_access_staticbuff_mutating { ptr in
					try secureZeroBytes(ptr, count:MemoryLayout<Result.Bytes32.RAW_staticbuff_storetype>.size)
				}
			} catch {
				tVar.valueRecv.RAW_access_staticbuff_mutating { ptr in
					ptr.initializeMemory(as:UInt8.self, repeating:0, count:MemoryLayout<Result.Bytes32.RAW_staticbuff_storetype>.size)
				}
			}
		}
	}
}
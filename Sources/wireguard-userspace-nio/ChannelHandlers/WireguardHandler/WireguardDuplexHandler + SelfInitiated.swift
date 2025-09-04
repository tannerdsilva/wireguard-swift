import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler {
	/// used to help match inbound handshake initiation responses with their corresponding peers. 
	internal struct ActivelyInitiatingIndex {
		private var publicKeyInitiationIndex:[PublicKey:PeerIndex] = [:]
		private var initiationIndexPublicKey:[PeerIndex:PublicKey] = [:]
		internal mutating func setActivelyInitiating(context:borrowing ChannelHandlerContext, publicKey:PublicKey, initiatorPeerIndex peerIndex:PeerIndex) -> PeerIndex? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard let outgoingPeerIndex = publicKeyInitiationIndex.updateValue(peerIndex, forKey:publicKey) else {
				// no existing value
				publicKeyInitiationIndex[publicKey] = peerIndex
				initiationIndexPublicKey[peerIndex] = publicKey
				return nil
			}
			guard initiationIndexPublicKey.removeValue(forKey:outgoingPeerIndex) == publicKey else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			initiationIndexPublicKey[peerIndex] = publicKey
			return outgoingPeerIndex
		}

		internal borrowing func match(context:borrowing ChannelHandlerContext, peerIndex:PeerIndex) -> PublicKey? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			return initiationIndexPublicKey[peerIndex]
		}

		internal mutating func removeIfExists(context:borrowing ChannelHandlerContext, peerIndex:PeerIndex) -> PublicKey? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard let publicKey = initiationIndexPublicKey.removeValue(forKey:peerIndex) else {
				// no existing value
				return nil
			}
			guard publicKeyInitiationIndex.removeValue(forKey:publicKey) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			return publicKey
		}

		internal mutating func removeIfExists(context:borrowing ChannelHandlerContext, publicKey:PublicKey) -> PeerIndex? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard let outgoingPeerIndex = publicKeyInitiationIndex.removeValue(forKey:publicKey) else {
				// no existing value
				return nil
			}
			guard initiationIndexPublicKey.removeValue(forKey:outgoingPeerIndex) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			return outgoingPeerIndex
		}
	}
}

extension PeerInfo.Live {
	/// used to store the data that should be written to the peer after the completion of a handshake.
	internal struct PendingPostHandshake {
		private var pendingWriteData:[(data:ByteBuffer, promise:EventLoopPromise<Void>?)] = []
		/// insert data into the write queue with a corresponding write promise.
		internal mutating func queue(data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			pendingWriteData.append((data:data, promise:promise))
		}
		/// remove and return the next item in the write queue, or nil if the queue is empty.
		internal mutating func dequeue() -> (data:ByteBuffer, promise:EventLoopPromise<Void>?)? {
			return pendingWriteData.isEmpty ? nil : pendingWriteData.removeFirst()
		}
		/// clears all pending data from the queue and passes the provided error to any write promises that are stored.
		internal mutating func clearAll<E>(error:E) where E:Swift.Error {
			for (_, promise) in pendingWriteData {
				promise?.fail(error)
			}
			pendingWriteData.removeAll()
		}
	}

	/// primary mechanism for storing chaining data for initiations sent outbound.
	internal struct CurrentSelfInitiatedInfo {
		private let responderStaticPublicKey:PublicKey
		private let wireguardHandler:Unmanaged<WireguardHandler>
		private var lastHandshakeEmissionTime:NIODeadline? = nil
		private var initiatorChainingData:(initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? = nil
		internal init(responderStaticPublicKey initiatorPub:PublicKey, handler:Unmanaged<WireguardHandler>) {
			wireguardHandler = handler
			responderStaticPublicKey = initiatorPub
		}

		/// calculates the amount of seconds that must be delayed before sending a handshake initiation in order to stay in conformance with the configured `WireguardHandler.rekeyTimeout`.
		/// - returns: the amount of time to delay, or nil if no delay is required
		internal mutating func handshakeRekeyDelay(context:borrowing ChannelHandlerContext, now:NIODeadline) -> TimeAmount? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard lastHandshakeEmissionTime != nil else {
				return nil
			}
			guard (lastHandshakeEmissionTime! + WireguardHandler.rekeyTimeout) > now else {
				return nil
			}
			return ((lastHandshakeEmissionTime! + WireguardHandler.rekeyTimeout) - now)
		}

		/// journals a new self-initiated message. this is called after a handshake is generated and before it is emitted.
		/// - parameters:
		/// 	- context: the channel handler context
		/// 	- now: the current time
		/// 	- ephemeralPrivateKey: the initiator's ephemeral private key
		/// 	- c: the initiator's chaining key
		/// 	- h: the initiator's handshake key
		/// 	- authenticatedPayload: the authenticated payload
		internal mutating func installInitiation(context:borrowing ChannelHandlerContext, now:NIODeadline, initiatorEphemeralPrivateKey ephemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			initiatorChainingData = (ephemeralPrivateKey, c, h, authenticatedPayload)
			lastHandshakeEmissionTime = now
			_ = wireguardHandler.takeUnretainedValue().automaticallyUpdatedVariables.activelyInitiatingIndicies.setActivelyInitiating(context:context, publicKey:responderStaticPublicKey, initiatorPeerIndex:authenticatedPayload.payload.initiatorPeerIndex)
		}

		/// called when a self-initiated handshake receives a response from the remote peer. this function validates that the responding peer index matches the expected value, and provides the cryptokey-set that was used for the initiation.
		/// - parameters:
		/// 	- context: the channel handler context
		/// 	- now: the current time
		/// 	- initiatorPeerIndex: the initiator's peer index
		/// - returns: the cryptokey-set that was used for the initiation, or nil if the claim was invalid
		internal mutating func claimInitiation(context:borrowing ChannelHandlerContext, now:NIODeadline, initiatorPeerIndex:PeerIndex) -> (initiatorEphemeralPrivateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, initiationPacket:Message.Initiation.Payload.Authenticated)? {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			guard initiatorPeerIndex == initiatorChainingData?.initiationPacket.payload.initiatorPeerIndex else {
				// the initiator peer index that invoked this remove event does not match the latest emitted packet
				return nil
			}
			guard (lastHandshakeEmissionTime! + WireguardHandler.rekeyTimeout) >= now else {
				// timeout exceeded, this handshake is no longer valid
				return nil
			}
			defer {
				initiatorChainingData = nil
			}
			guard wireguardHandler.takeUnretainedValue().automaticallyUpdatedVariables.activelyInitiatingIndicies.removeIfExists(context:context, publicKey:responderStaticPublicKey) == initiatorPeerIndex else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			return initiatorChainingData
		}
	}
}

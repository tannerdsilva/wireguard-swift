import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension WireguardHandler.SelfInitiatedIndexes {
	/// primary mechanism for storing chaining data for initiations sent outbound
	private struct Keys {
		private var initiatorEphemeralPrivateKey:[PeerIndex:MemoryGuarded<PrivateKey>] = [:]
		private var initiatorChainingData:[PeerIndex:(c:Result.Bytes32, h:Result.Bytes32)] = [:]
		private var initiatorPackets:[PeerIndex:Message.Initiation.Payload.Authenticated] = [:]
		fileprivate mutating func install(index:PeerIndex, privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated) {
			initiatorEphemeralPrivateKey[index] = privateKey
			initiatorChainingData[index] = (c:c, h:h)
			initiatorPackets[index] = authenticatedPayload
		}
		fileprivate mutating func remove(index:PeerIndex) -> (privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated)? {
			guard	let chTuple = initiatorChainingData.removeValue(forKey:index),
					let ephiKey = initiatorEphemeralPrivateKey.removeValue(forKey:index),
					let authPacket = initiatorPackets.removeValue(forKey:index) else {
				return nil
			}
			return (privateKey:ephiKey, c:chTuple.c, h:chTuple.h, authenticatedPayload:authPacket)
		}
	}
}

extension WireguardHandler.SelfInitiatedIndexes {
	private struct RecurringRekey {
		private var rekeyAttemptTasks:[PeerIndex:RepeatedTask] = [:]
		fileprivate mutating func startRecurringRekey(interval:TimeAmount, for peerIndex:PeerIndex, context:ChannelHandlerContext, _ task:@escaping(RepeatedTask) throws -> Void) {
			guard let oldRecurringTask = rekeyAttemptTasks.updateValue(context.eventLoop.scheduleRepeatedTask(initialDelay:interval, delay:interval, notifying:nil, task), forKey:peerIndex) else {
				return
			}
			oldRecurringTask.cancel()
		}
		fileprivate mutating func endRecurringRekey(for peerIndex:PeerIndex) {
			guard let hasExistingTask = rekeyAttemptTasks.removeValue(forKey:peerIndex) else {
				return
			}
			hasExistingTask.cancel()
		}
	}
}

extension WireguardHandler {
	internal struct SelfInitiatedIndexes {
		private var chainingKeys:Keys = Keys()
		private var recurringRekeys = RecurringRekey()
		private var indexMPublicKey:[PeerIndex:PublicKey] = [:]
		private var publicKeyIndexM:[PublicKey:PeerIndex] = [:]
		internal mutating func journal(context:ChannelHandlerContext, indexM index:PeerIndex, publicKey:PublicKey, chainingData:(privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated), _ task:@escaping(RepeatedTask) throws -> Void) {
			defer {
				chainingKeys.install(index:index, privateKey:chainingData.privateKey, c:chainingData.c, h:chainingData.h, authenticatedPayload:chainingData.authenticatedPayload)
				recurringRekeys.startRecurringRekey(interval:WireguardHandler.rekeyTimeout, for:index, context:context, task)
			}
			guard let oldInitiationIndex = publicKeyIndexM.updateValue(index, forKey:publicKey) else {
				indexMPublicKey[index] = publicKey
				return
			}
			defer {
				_ = chainingKeys.remove(index:oldInitiationIndex)
				recurringRekeys.endRecurringRekey(for:oldInitiationIndex)
			}
			guard indexMPublicKey.removeValue(forKey:oldInitiationIndex) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			indexMPublicKey[index] = publicKey
		}
		
		internal mutating func extract(indexM index:PeerIndex) -> (peerPublicKey:PublicKey, privateKey:MemoryGuarded<PrivateKey>, c:Result.Bytes32, h:Result.Bytes32, authenticatedPayload:Message.Initiation.Payload.Authenticated)? {
			guard let extractedPublicKey = indexMPublicKey.removeValue(forKey:index) else {
				// index never existed
				return nil
			}
			guard publicKeyIndexM.removeValue(forKey:extractedPublicKey) != nil else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			recurringRekeys.endRecurringRekey(for:index)
			let extractedData = chainingKeys.remove(index:index)!
			return (peerPublicKey:extractedPublicKey, privateKey:extractedData.privateKey, c:extractedData.c, h:extractedData.h, authenticatedPayload:extractedData.authenticatedPayload)
		}
		
		@discardableResult internal mutating func clear(publicKey:PublicKey) -> PeerIndex? {
			guard let hasExistingPeerIndex = publicKeyIndexM.removeValue(forKey:publicKey) else {
				return nil
			}
			guard indexMPublicKey.removeValue(forKey:hasExistingPeerIndex) == publicKey else {
				fatalError("internal data consistency error. this is a critical internal error that should never occur in real code. \(#file):\(#line)")
			}
			recurringRekeys.endRecurringRekey(for:hasExistingPeerIndex)
			_ = chainingKeys.remove(index:hasExistingPeerIndex)
			return hasExistingPeerIndex
		}
	}
}
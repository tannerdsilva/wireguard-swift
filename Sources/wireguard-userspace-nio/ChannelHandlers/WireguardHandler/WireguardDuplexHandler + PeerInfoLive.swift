import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension PeerInfo.Live {
	private struct PendingPostHandshake {
		private var pendingWriteData:[(data:ByteBuffer, promise:EventLoopPromise<Void>?)] = []
		internal mutating func queue(data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			pendingWriteData.append((data:data, promise:promise))
		}
	}
}

extension PeerInfo {
	internal final class Live {
		private let log:Logger
		internal let publicKey:PublicKey
		
		private var ep:Endpoint?
		
		internal var persistentKeepalive:TimeAmount?
		internal var handshakeInitiationTime:TAI64N? = nil

		private var rotation:Rotating<HandshakeGeometry<PeerIndex>>
		
		private var postHandshakePackets = PendingPostHandshake()

		private struct SendReceive<SendType, ReceiveType> {
			internal var valueSend:SendType
			internal var valueRecv:ReceiveType
			fileprivate init(valueSend vs:SendType, valueRecv vr:ReceiveType) {
				valueSend = vs
				valueRecv = vr
			}
			fileprivate init(peerInitiated inputTuple:(SendType, ReceiveType)) {
				valueSend = inputTuple.0
				valueRecv = inputTuple.1
			}
			fileprivate init(selfInitiated inputTuple:(SendType, ReceiveType)) where SendType == ReceiveType {
				valueSend = inputTuple.1
				valueRecv = inputTuple.0
			}
		}
		private var nVars:[HandshakeGeometry<PeerIndex>:SendReceive<Counter, SlidingWindow<Counter>>] = [:]
		private var tVars:[HandshakeGeometry<PeerIndex>:SendReceive<Result.Bytes32, Result.Bytes32>] = [:]
		
		internal init(_ peerInfo:PeerInfo, context:ChannelHandlerContext, logLevel:Logger.Level) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_peer"] = "\(peerInfo.publicKey)"
			log = buildLogger

			publicKey = peerInfo.publicKey
			ep = peerInfo.endpoint
			persistentKeepalive = peerInfo.internalKeepAlive
			rotation = Rotating<HandshakeGeometry<PeerIndex>>()
		}
		
		internal func getSendVars() -> (nSend:Counter, tSend:Result.Bytes32, geometry:HandshakeGeometry<PeerIndex>)? {
			guard let currentGeometry = rotation.current else {
				// no active handshakes
				return nil
			}
			return (nSend:nVars[currentGeometry]!.valueSend, tSend:tVars[currentGeometry]!.valueSend, geometry:currentGeometry)
		}

		internal func nSendUpdate(_ nSend:Counter, geometry:HandshakeGeometry<PeerIndex>) {
			guard var currentNVar = nVars[geometry] else {
				fatalError("no nVar for geometry \(geometry) \(#file):\(#line)")
			}
			currentNVar.valueSend = nSend
			nVars[geometry] = currentNVar
		}
		
		internal borrowing func queuePostHandshake(context:ChannelHandlerContext, data:ByteBuffer, promise:EventLoopPromise<Void>?) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			postHandshakePackets.queue(data:data, promise:promise)
		}
		
		/// retrieve the previously known endpoint for the peer
		internal borrowing func endpoint() -> Endpoint? {
			return ep
		}
	
		/// journal the endpoint that the peer has been observed at
		internal borrowing func updateEndpoint(_ inputEndpoint:Endpoint) {
			guard ep != inputEndpoint else {
				return
			}
			ep = inputEndpoint
			log.info("peer roamed to new endopint", metadata:["endpoint_remote":"\(inputEndpoint)"])
		}
		
		internal borrowing func currentRotation() -> HandshakeGeometry<PeerIndex>? {
			return rotation.current
		}
		
		internal func applyPeerInitiated(_ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws -> HandshakeGeometry<PeerIndex>? {
			#if DEBUG
			guard case .peerInitiated(m:_, mp:_) = element else {
				fatalError("self initiated geometry used on peer initiated function. \(#file):\(#line)")
			}
			#endif
			nVars.updateValue(SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), forKey:element)
			tVars.updateValue(SendReceive<Result.Bytes32, Result.Bytes32>(peerInitiated:try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)), forKey:element)
			log.info("rotation applied for peer initiated data")
			guard let outgoingIndexValue = rotation.apply(next:element) else {
				// no outgoing index value, return
				return nil
			}
			// clean up the outgoing index value
			nVars.removeValue(forKey:outgoingIndexValue)
			tVars.removeValue(forKey:outgoingIndexValue)
			return outgoingIndexValue
		}
		
		internal func applySelfInitiated(_ element:HandshakeGeometry<PeerIndex>, cPtr:UnsafeRawPointer, count:Int) throws -> (previous:HandshakeGeometry<PeerIndex>?, next:HandshakeGeometry<PeerIndex>?) {
			#if DEBUG
			guard case .selfInitiated(m:_, mp:_) = element else {
				fatalError("peer initiated geometry used on self initiated function. \(#file):\(#line)")
			}
			#endif
			nVars.updateValue(SendReceive<Counter, SlidingWindow<Counter>>(valueSend:0, valueRecv:SlidingWindow(windowSize:64)), forKey:element)
			tVars.updateValue(SendReceive<Result.Bytes32, Result.Bytes32>(selfInitiated:try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key:cPtr, count:MemoryLayout<Result.Bytes32>.size, data:[] as [UInt8], count:0)), forKey:element)
			log.info("rotation applied for self initiated data")
			let rotationResults = rotation.rotate(replacingNext:element)
			if let outgoingPrevious = rotationResults.previous {
				nVars.removeValue(forKey:outgoingPrevious)
				tVars.removeValue(forKey:outgoingPrevious)
			}
			if let outgoingNext = rotationResults.next {
				nVars.removeValue(forKey:outgoingNext)
				tVars.removeValue(forKey:outgoingNext)
			}
			return rotationResults
		}
	}
}

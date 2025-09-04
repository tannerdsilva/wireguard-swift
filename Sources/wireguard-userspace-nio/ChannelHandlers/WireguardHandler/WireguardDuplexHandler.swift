import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

internal final class WireguardHandler:ChannelDuplexHandler, @unchecked Sendable {
	/// the type of value that is emitted by this handler to notify downstream inbound handlers that handshakes have occurred on the interface.
	internal struct WireguardHandshakeNotification {
		/// the start date of the handshake session as per the wireguard whitepaper
		// internal let sessionStartDate:NIODeadline
		/// the public key of the peer that initiated the handshake
		internal let publicKey:PublicKey
	}

	internal typealias InboundIn = (Endpoint, Message.NIO)
	internal typealias InboundOut = (PublicKey, ByteBuffer)
	internal typealias OutboundIn = (PublicKey, ByteBuffer)
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>
	
	internal static let rekeyTimeout = TimeAmount.seconds(5)
	internal static let rekeyAttemptTime = TimeAmount.seconds(90)
	
	private enum State {
		case initialized([PeerInfo])
		case channelEngaged
		case terminated
	}
	
	internal var secretCookieR:Result.Bytes8 = try! generateSecureRandomBytes(as:Result.Bytes8.self)
	
	/// logger that will be used to produce output for the work completed by this handler
	private let log:Logger
	private let privateKey:MemoryGuarded<PrivateKey>
	internal let precomputedCookieKey:RAW_xchachapoly.Key
	
	internal let isCongested:Atomic<Bool> = .init(false)

	/// stored variables of the WireguardHandler that are automatically managed through Unmanaged instances of the WireguardHandler being stored in sub-structures.
	internal struct AutomaticallyUpdated {
		/// initiation indicies.
		/// - NOTE: this variable is modified directly by the PeerIndex.Live instances.
		internal var activelyInitiatingIndicies:ActivelyInitiatingIndex
		/// active session indicies.
		/// - NOTE: this variable is modified directly by the PeerIndex.Live instances.
		internal var activeSessionIndicies:MPeerIndex
	}

	/// NOTE: do not touch - the live peer instances will mutate these for you.
	internal var automaticallyUpdatedVariables:AutomaticallyUpdated
	/// the primary storage for the active peers that the interface will connect to.
	private var peerDeltaEngine:PeerDeltaEngine!
	/// the buffer used for encoding messages before sending them over the network.
	private var encodeBuffer:ByteBuffer!
	/// the current operational state of the handler.
	private var operatingState:State

	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, initialPeers:consuming [PeerInfo], logLevel:Logger.Level) {
		privateKey = pkIn
		let publicKey = PublicKey(privateKey: privateKey)
		automaticallyUpdatedVariables = AutomaticallyUpdated(activelyInitiatingIndicies:ActivelyInitiatingIndex(), activeSessionIndicies:AutomaticallyUpdated.MPeerIndex(logLevel:logLevel))
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		buildLogger[metadataKey:"public-key_self"] = "\(publicKey)"
		log = buildLogger
		
		// pre-computing HASH(LABEL-COOKIE || Spub)
		var hasher = try! WGHasher<RAW_xchachapoly.Key>()
		try! hasher.update([UInt8]("cookie--".utf8))
		try! hasher.update(publicKey)
		precomputedCookieKey = try! hasher.finish()
		
		log.trace("instance initialized", metadata:["peer_count":"\(initialPeers.count)"])
		operatingState = .initialized(initialPeers)
	}

	internal func writeMessage(_ message:Message, to destinationEndpoint:Endpoint, context:ChannelHandlerContext, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var mesLen = 0
		message.RAW_encode(count:&mesLen)
		encodeBuffer.clear(minimumCapacity:mesLen)
		encodeBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:mesLen) { outputBuffer in
			return outputBuffer.baseAddress!.distance(to:message.RAW_encode(dest:outputBuffer.baseAddress!.assumingMemoryBound(to:UInt8.self)))
		}
		let asAddressedEnvelope = AddressedEnvelope<ByteBuffer>(remoteAddress: SocketAddress(destinationEndpoint), data: encodeBuffer)
		context.writeAndFlush(wrapOutboundOut(asAddressedEnvelope), promise:promise)
	}
}

extension WireguardHandler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		switch operatingState {
			case .initialized(let initPeers):
				encodeBuffer = context.channel.allocator.buffer(capacity:1800)
				peerDeltaEngine = PeerDeltaEngine(context:context, initiallyConfigured:initPeers, handler:self, additionHandler: { [weak self, l = log] _ in 
					// when peer is added
					guard let self = self else { return }
				}, removalHandler: { [weak self, l = log] removedPublicKey in
					// when peer is removed
					guard let self = self else { return }
					l.info("removing peer from interface", metadata:["public-key_removed":"\(removedPublicKey)"])
				})
				operatingState = .channelEngaged
			default:
				fatalError("this should never happen \(#file):\(#line)")
		}
		logger.trace("handler added to NIO pipeline.")
	}
	internal func handlerRemoved(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		logger.trace("handler removed from NIO pipeline.")
		operatingState = .terminated
	}
	internal func userInboundEventTriggered(context: ChannelHandlerContext, event:Any) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var logger = log
		logger.trace("user inbound event triggered")
	}
}

// swift nio read handler function
extension WireguardHandler {
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let now = NIODeadline.now()
		var logger = log
		// handles handshake packets, else passes them down
		do {
			let (endpoint, payload) = unwrapInboundIn(data)
			logger[metadataKey:"endpoint_remote"] = "\(endpoint)"
			switch payload {
				case .initiation(let payload):
					/*
					peers role: initiator
					our role: responder
					=================
					Im = responder peer index
					Im' = initiator peer index
					*/
					if isCongested.load(ordering:.acquiring) == true {
						do {
							try payload.validateUnderLoadNoNIO(responderStaticPrivateKey:privateKey, R:secretCookieR, endpoint:endpoint)
						} catch Message.Initiation.Payload.Authenticated.Error.mac1Invalid {
							logger.error("received invalid handshake initiation packet. ignoring.")
							return
						} catch let error {
							// create and send the cookie
							let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
							writeMessage(.cookie(cookie), to:endpoint, context:context, promise:nil)
							return
						}
					}
					
					let responderPeerIndex = try generateSecureRandomBytes(as:PeerIndex.self)
					var (c, h, initiatorStaticPublicKey, timestamp) = try payload.validate(responderStaticPrivateKey: privateKey)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:initiatorStaticPublicKey) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(initiatorStaticPublicKey)"])
						return
					}
					
					let geometry = HandshakeGeometry<PeerIndex>.peerInitiated(m:responderPeerIndex, mp:payload.payload.initiatorPeerIndex)

					livePeerInfo.updateEndpoint(endpoint)
					livePeerInfo.handshakeInitiationTime = timestamp
					try livePeerInfo.applyPeerInitiated(context:context, geometry, cPtr:&c, count:MemoryLayout<Result.Bytes32>.size)
					let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
					let response = try Message.Response.Payload.forge(c:c, h:h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &initiatorStaticPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey, responderPeerIndex:responderPeerIndex)
					let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&initiatorStaticPublicKey)
					logger.debug("successfully validated handshake initiation", metadata:["index_initiator":"\(payload.payload.initiatorPeerIndex)", "index_responder":"\(responderPeerIndex)", "public-key_remote":"\(initiatorStaticPublicKey)"])
					writeMessage(.response(authResponse), to:endpoint, context:context, promise:nil)
					break;
				case .response(let payload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
					guard let peerPub = automaticallyUpdatedVariables.activelyInitiatingIndicies.match(context:context, peerIndex:payload.payload.initiatorIndex) else {
						logger.critical("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:peerPub) else {
						logger.critical("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					guard var chainingData = try livePeerInfo.handshakeInitiationResponse(context:context, now:now, initiatorPeerIndex:payload.payload.initiatorIndex) else {
						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					let val = try payload.validate(c:chainingData.c, h:chainingData.h, initiatorStaticPrivateKey:privateKey, initiatorEphemeralPrivateKey:chainingData.initiatorEphemeralPrivateKey, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
					let geometry = HandshakeGeometry<PeerIndex>.selfInitiated(m:payload.payload.initiatorIndex, mp:payload.payload.responderIndex)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:peerPub) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(peerPub)"])
						return
					}
					livePeerInfo.updateEndpoint(endpoint)
					try livePeerInfo.applySelfInitiated(context:context, geometry, cPtr:&chainingData.c, count:MemoryLayout<Result.Bytes32>.size)
					logger.debug("successfully validated handshake response", metadata:["index_initiator":"\(payload.payload.initiatorIndex)", "index_responder":"\(payload.payload.responderIndex)", "public-key_remote":"\(peerPub)"])
					context.fireUserInboundEventTriggered(WireguardHandshakeNotification(/*sessionStartDate:now, */publicKey:peerPub))
					break;
				case .cookie(let cookiePayload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
//					guard let peerInfo = peerDeltaEngine[
					logger.debug("received cookie packet", metadata:["public-key_remote":""])
					/*withUnsafePointer(to:peerPub) { expectedPeerPublicKey in
						var phantomCookie:Message.Initiation.Payload.Authenticated
						do {
							phantomCookie = try chainingData.authenticatedPayload.payload.finalize(responderStaticPublicKey:expectedPeerPublicKey, cookie:cookiePayload)
//							selfInitiatedInfo.initiatorPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
						} catch {
//							logger.error("failed to validate cookie and create msgMac2")
//							return
						}
						let nioNow = NIODeadline.now()
						selfInitiatedIndexes.rekey(context:context, indexM:cookiePayload.receiverIndex, publicKey:expectedPeerPublicKey.pointee, chainingData:(privateKey:chainingData.privateKey, c:chainingData.c, h:chainingData.h, authenticatedPayload:chainingData.authenticatedPayload)) { [weak self, ap = chainingData.authenticatedPayload, start = nioNow, c = ContextContainer(context:context), endpoint = endpoint] timer in
							// rekey attempt task.
							guard let self = self, NIODeadline.now() - start < Self.rekeyAttemptTime else {
								// recurring task should no longer be running
								timer.cancel()
								return
							}
							// write another initiation packet
							c.accessContext { contextPointer in
								self.writeMessage(.initiation(ap), to:endpoint, context:contextPointer.pointee, promise:nil)
							}
						}
					}*/
					break;
				
				case .data(recipientIndex: let recipientIndex, counter: let counter, payload: let payload):
					// verify that a current peer index exists for the public key already.
					guard let identifiedPublicKey = automaticallyUpdatedVariables.activeSessionIndicies.seek(indexM:recipientIndex) else {
						logger.error("could not find matching traffic for inbound data peer index m \(recipientIndex)")
						return
					}
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:identifiedPublicKey) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(identifiedPublicKey)"])
						return
					}
					guard let existingGeometryPositioned = livePeerInfo.session(forPeerM:recipientIndex) else {
						logger.critical("could not find matching traffic for inbound data peer index m \(recipientIndex)")
						return
					}
					let session = existingGeometryPositioned.element
					let existingGeometry = session.geometry
					var varsRecv = livePeerInfo.getRecvVars(geometry:existingGeometryPositioned)!
					guard varsRecv.nRecv.isPacketAllowed(counter.RAW_native()) else {
						logger.warning("sliding window rejected packet", metadata:["public-key_remote":"\(identifiedPublicKey)", "nRecv":"\(varsRecv.nRecv)", "tRecv":"\(varsRecv.tRecv.debugDescription)", "counter":"\(counter.RAW_native())"])
						return
					}
					encodeBuffer.clear(minimumCapacity:payload.count - MemoryLayout<Tag>.size)
					try encodeBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:payload.count - MemoryLayout<Tag>.size) { decrypted in
						return try payload.withUnsafeBytes { dataBuffer in
							let lenWithoutTag = dataBuffer.count - MemoryLayout<Tag>.size
							let dataRegion = UnsafeRawBufferPointer(start:dataBuffer.baseAddress, count:lenWithoutTag)
							let tagRegion = dataBuffer.baseAddress!.advanced(by:lenWithoutTag)
							try Message.Data.Payload.decrypt(transportKey:varsRecv.tRecv, counter:counter, cipherText:dataRegion, tag:tagRegion, aad:UnsafeRawBufferPointer(start:dataRegion.baseAddress!, count:0), plainText:decrypted.baseAddress!)	
							return payload.count - MemoryLayout<Tag>.size
						}
					}

					switch existingGeometryPositioned {
						case .next(let nextGeometry):
							_ = livePeerInfo.applyRotation(context:context)
						default:
							break
					}

					guard encodeBuffer.readableBytes != 0 else {
						// keepalive packet
						logger.debug("received keepalive packet", metadata:["public-key_remote":"\(identifiedPublicKey)"])
						return
					}

					context.fireChannelRead(wrapInboundOut((identifiedPublicKey, encodeBuffer)))
			}
		} catch let error {
			logger.error("error processing packet: \(error)")
			context.fireErrorCaught(error)
		}
	}
}

// swift nio write handler function
extension WireguardHandler {
	internal func writeBytes(context:ChannelHandlerContext, publicKey:PublicKey, payload:inout ByteBuffer, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		let now = NIODeadline.now()
		logger[metadataKey: "public-key_remote"] = "\(publicKey)"
		guard let peerInfoLive = peerDeltaEngine.peerLookup(publicKey:publicKey) else {
			logger.error("peer is not configured. can not write data.")
			promise?.fail(UnknownPeerEndpoint())
			return
		}
		guard let ep = peerInfoLive.endpoint() else {
			logger.error("trying to write data to a peer with no known endpoint.")
			promise?.fail(UnknownPeerEndpoint())
			return
		}
		guard let (nSendCur, tSend, currentHandshakeGeometry) = peerInfoLive.getSendVars(now:now) else {
			// need to send a handshake and then the data can be sent
			do {
				try peerInfoLive.launchHandshakeInitiationTask(context:context, now:now, endpointOverride:ep, initiatorStaticPrivateKey:privateKey)
			} catch is PeerInfo.Live.HandshakeTaskAlreadyRunning {
				// do nothing
			} catch let error {
				logger.error("error thrown while trying to launch handshake initiation task", metadata:["error":"\(error)"])
				context.fireErrorCaught(error)
				promise?.fail(error)
				return
			}
			peerInfoLive.queuePostHandshake(context:context, data:payload, promise:promise)
			return
		}
		var nSend = nSendCur
		do {
			var forgedLength = 0
			forgedLength += MemoryLayout<Message.Data.Header>.size
			forgedLength += MemoryLayout<Tag>.size
			forgedLength += Message.Data.Payload.paddedLength(count:payload.readableBytes)
			logger.trace("forged length computed", metadata:["length":"\(forgedLength)", "padding_length":"\(Message.Data.Payload.paddedLength(count:payload.readableBytes) - payload.readableBytes)"])
			encodeBuffer.clear(minimumCapacity:forgedLength)
			try encodeBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:forgedLength) { bufferPtr in
				return try Message.Data.Payload.forge(receiverIndex:currentHandshakeGeometry.mp, nonce:&nSend, transportKey:tSend, plainText:&payload, output:bufferPtr.baseAddress!)
			}
		} catch let error {
			logger.error("error thrown while trying to write outbound data", metadata:["error":"\(error)"])
			context.fireErrorCaught(error)
			promise?.fail(error)
			return
		}
		peerInfoLive.nSendUpdate(nSend, geometry:currentHandshakeGeometry)
		let asAddressedEnvelope = AddressedEnvelope<ByteBuffer>(remoteAddress: SocketAddress(ep), data:encodeBuffer)
		context.writeAndFlush(wrapOutboundOut(asAddressedEnvelope), promise:promise)
	}

	/// thrown when a handshake initiation is attempted on a peer with no documented endpoint
	internal struct UnknownPeerEndpoint:Swift.Error {}
	/// thrown when a rekey attempt is made before the rekey timer will allow for the next rekey event
	internal struct RekeyAttemptTooSoon:Swift.Error {}
	
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var (publicKey, payload) = unwrapOutboundIn(data)
		writeBytes(context:context, publicKey:publicKey, payload:&payload, promise:promise)
	}
}
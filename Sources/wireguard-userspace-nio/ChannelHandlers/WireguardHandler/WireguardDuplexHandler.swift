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
		internal let sessionStartDate:NIODeadline
		/// the public key of the peer that initiated the handshake
		internal let publicKey:PublicKey
		/// the geometry of the handshake that was completed
		internal let geometry:HandshakeGeometry<PeerIndex>
	}

	internal typealias InboundIn = (Endpoint, Message.NIO)
	internal typealias InboundOut = PeerAssociated<ByteBuffer>
	internal typealias OutboundIn = PeerAssociated<ByteBuffer>
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>
	private var outboundOutDriver:WriteOrHold<OutboundOut>
	
	internal static let keepaliveTimeout = TimeAmount.seconds(10)
	internal static let rekeyTimeout = TimeAmount.seconds(5)
	internal static let rekeyAttemptTime = TimeAmount.seconds(90)
	internal static let rekeyAfterTime = TimeAmount.seconds(120)
	internal static let rejectAfterTime = TimeAmount.seconds(300)

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

	/// the maximum transmission unit that is configured for this handler.
	private let mtu:UInt16

	/// WARNING: do not touch - the live peer instances will mutate these for you.
	internal var automaticallyUpdatedVariables:AutomaticallyUpdated
	/// the primary storage for the active peers that the interface will connect to.
	private var peerDeltaEngine:PeerDeltaEngine!
	/// the buffer used for encoding messages before sending them over the network.
	internal var encodeBuffer:ByteBuffer!
	/// the current operational state of the handler.
	private var operatingState:State

	/// used to indicate that a flush should be performed after channelReadComplete is called. returns back to false after channelReadComplete is called.
	internal var flushAfterChannelReadComplete:Bool = false

	internal init(privateKey pkIn:MemoryGuarded<PrivateKey>, mtu:inout UInt16, initialPeers:consuming [PeerInfo], logLevel:Logger.Level) {
		privateKey = pkIn
		let publicKey = PublicKey(privateKey: privateKey)
		automaticallyUpdatedVariables = AutomaticallyUpdated(activelyInitiatingIndicies:AutomaticallyUpdated.ActivelyInitiatingIndex(), activeSessionIndicies:AutomaticallyUpdated.MPeerIndex(logLevel:logLevel))
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		buildLogger[metadataKey:"public-key_self"] = "\(publicKey)"
		log = buildLogger
		
		// pre-computing HASH(LABEL-COOKIE || Spub)
		var hasher = try! WGHasher<RAW_xchachapoly.Key>()
		try! hasher.update([UInt8]("cookie--".utf8))
		try! hasher.update(publicKey)
		precomputedCookieKey = try! hasher.finish()
		operatingState = .initialized(initialPeers)
		self.mtu = mtu
		mtu -= UInt16(MemoryLayout<Message.Data.Header>.size + MemoryLayout<Tag>.size)
		outboundOutDriver = WriteOrHold(logLevel:log.logLevel, limit:2048)
	}

	internal func writeMessage(_ message:Message, to destinationEndpoint:Endpoint, context:ChannelHandlerContext, promise:EventLoopPromise<Void>?) -> WriteOrHold<OutboundOut>.Result {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		var mesLen = 0
		message.RAW_encode(count:&mesLen)
		encodeBuffer.clear(minimumCapacity:mesLen)
		encodeBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:mesLen) { outputBuffer in
			return outputBuffer.baseAddress!.distance(to:message.RAW_encode(dest:outputBuffer.baseAddress!.assumingMemoryBound(to:UInt8.self)))
		}
		let asAddressedEnvelope = AddressedEnvelope<ByteBuffer>(remoteAddress:SocketAddress(destinationEndpoint), data:encodeBuffer)
		context.write(wrapOutboundOut(asAddressedEnvelope), promise:promise)
		return outboundOutDriver.holdOrWrite(context:context, handler:self, asAddressedEnvelope, writePromise:promise)
	}
}

extension WireguardHandler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		let logger = log
		switch operatingState {
			case .initialized(let initPeers):
				encodeBuffer = context.channel.allocator.buffer(capacity:1800)
				peerDeltaEngine = PeerDeltaEngine(context:context, initiallyConfigured:initPeers, handler:self, logLevel:logger.logLevel, additionHandler: { [weak self] _ in
					// when peer is added
					guard let _ = self else { return }
				}, removalHandler: { [weak self, l = log] removedPublicKey, _ in
					// when peer is removed
					guard let _ = self else { return }
					l.debug("removing peer from interface", metadata:["public-key_removed":"\(removedPublicKey)"])
				})
				operatingState = .channelEngaged
			default:
				fatalError("this should never happen \(#file):\(#line)")
		}
		logger.debug("handler added to NIO pipeline.", metadata:["mtu_wire":"\(mtu)", "mtu_user":"\(mtu - UInt16(MemoryLayout<Message.Data.Header>.size + MemoryLayout<Tag>.size))"])
	}
	internal func handlerRemoved(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		let logger = log
		logger.debug("handler removed from NIO pipeline.")
		operatingState = .terminated
		peerDeltaEngine.setPeers(context:context, [], handler:self)
	}
	internal func userInboundEventTriggered(context: ChannelHandlerContext, event:Any) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		let logger = log
		logger.trace("user inbound event triggered")
	}
}

// swift nio read handler function
extension WireguardHandler {
	internal func channelReadComplete(context: ChannelHandlerContext) {
		defer {
			flushAfterChannelReadComplete = false
			context.fireChannelReadComplete()
		}
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		if flushAfterChannelReadComplete == true {
			log.trace("flushing after channel read complete.")
			context.flush()
		}
	}
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
						} catch {
							// create and send the cookie
							let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex:payload.payload.initiatorPeerIndex, k:precomputedCookieKey, r:secretCookieR, endpoint:endpoint, m:payload.msgMac1)
							switch writeMessage(.cookie(cookie), to:endpoint, context:context, promise:nil) {
								case .written:
									flushAfterChannelReadComplete = true
								default:
									// held - no need to flush now.
									break
							}
						}
					}
					
					let responderPeerIndex = try generateSecureRandomBytes(as:PeerIndex.self)
					var (c, h, initiatorStaticPublicKey, _) = try payload.validate(responderStaticPrivateKey: privateKey)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:initiatorStaticPublicKey) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(initiatorStaticPublicKey)"])
						return
					}
					
					let geometry = HandshakeGeometry<PeerIndex>.peerInitiated(m:responderPeerIndex, mp:payload.payload.initiatorPeerIndex)
					livePeerInfo.updateEndpoint(endpoint)
					try livePeerInfo.applyPeerInitiated(context:context, now:now, geometry, cPtr:&c, count:MemoryLayout<Result.Bytes32>.size)
					let sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
					let response = try Message.Response.Payload.forge(c:c, h:h, initiatorPeerIndex:payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &initiatorStaticPublicKey, initiatorEphemeralPublicKey:payload.payload.ephemeral, preSharedKey:sharedKey, responderPeerIndex:responderPeerIndex)
					let authResponse = try response.payload.finalize(initiatorStaticPublicKey:&initiatorStaticPublicKey)
					logger.debug("successfully validated handshake initiation. writing and flushing handshake response...", metadata:["index_initiator":"\(payload.payload.initiatorPeerIndex)", "index_responder":"\(responderPeerIndex)", "public-key_remote":"\(initiatorStaticPublicKey)"])
					switch writeMessage(.response(authResponse), to:endpoint, context:context, promise:nil) {
						case .written:
							flushAfterChannelReadComplete = true
						default:
							// held - no need to flush now.
							break
					}
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
					guard var chainingData = livePeerInfo.handshakeInitiationResponse(context:context, now:now, initiatorPeerIndex:payload.payload.initiatorIndex) else {
						logger.error("received handshake response for unknown peer index \(payload.payload.initiatorIndex) with no existing ephemeral private key")
						return
					}
					let _ = try payload.validate(c:chainingData.c, h:chainingData.h, initiatorStaticPrivateKey:privateKey, initiatorEphemeralPrivateKey:chainingData.initiatorEphemeralPrivateKey, preSharedKey:Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()))
					let geometry = HandshakeGeometry<PeerIndex>.selfInitiated(m:payload.payload.initiatorIndex, mp:payload.payload.responderIndex)
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:peerPub) else {
						logger.notice("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(peerPub)"])
						return
					}
					livePeerInfo.updateEndpoint(endpoint)
					try livePeerInfo.applySelfInitiated(context:context, now:now, geometry, cPtr:&chainingData.c, count:MemoryLayout<Result.Bytes32>.size)
					logger.debug("successfully validated handshake response", metadata:["index_initiator":"\(payload.payload.initiatorIndex)", "index_responder":"\(payload.payload.responderIndex)", "public-key_remote":"\(peerPub)"])
					break;
					
				case .cookie(let cookiePayload):
					/*
					peers role: responder
					our role: initiator
					=================
					Im = initiator peer index
					Im' = responder peer index
					*/
					guard let peerPub = automaticallyUpdatedVariables.activelyInitiatingIndicies.match(context:context, peerIndex:cookiePayload.receiverIndex) else {
						logger.critical("received cookie packet for unknown peer index \(cookiePayload.receiverIndex) with no existing ephemeral private key")
						return
					}
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:peerPub) else {
						logger.critical("received cookie packet for unknown peer index \(cookiePayload.receiverIndex) with no existing ephemeral private key")
						return
					}
					guard let chainingData = livePeerInfo.handshakeInitiationResponse(context:context, now:now, initiatorPeerIndex:cookiePayload.receiverIndex) else {
						logger.error("received cookie packet for unknown peer index \(cookiePayload.receiverIndex) with no existing ephemeral private key")
						return
					}
					logger.debug("received cookie packet", metadata:["public-key_remote":""])
					withUnsafePointer(to:peerPub) { expectedPeerPublicKey in
						var phantomCookie:Message.Initiation.Payload.Authenticated
						do {
							phantomCookie = try chainingData.initiationPacket.payload.finalize(responderStaticPublicKey:expectedPeerPublicKey, cookie:cookiePayload)
//							selfInitiatedInfo.initiatorPackets[initiationPacket.payload.initiatorPeerIndex] = phantomCookie
						} catch {
//							logger.error("failed to validate cookie and create msgMac2")
//							return
						}
						/*let nioNow = NIODeadline.now()
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
						}*/
					}
					break;
				
				case .data(recipientIndex: let recipientIndex, counter: let counter, payload: let payload):
					// verify that a current peer index exists for the public key already.
					guard let identifiedPublicKey = automaticallyUpdatedVariables.activeSessionIndicies.seek(indexM:recipientIndex) else {
						logger.warning("could not find matching traffic for inbound data peer index m \(recipientIndex)")
						return
					}
					guard let livePeerInfo = peerDeltaEngine.peerLookup(publicKey:identifiedPublicKey) else {
						logger.warning("interface not configured to operate with remote peer", metadata:["public-key_remote":"\(identifiedPublicKey)"])
						return
					}
					// load the cryptokeys that correspond to this peer index.
					guard let existingGeometryPositioned = livePeerInfo.session(forPeerM:recipientIndex) else {
						logger.warning("could not find matching traffic for inbound data peer index m \(recipientIndex)")
						return
					}
					var varsRecv = livePeerInfo.getRecvVars(context:context, geometry:existingGeometryPositioned, now:now)!
					guard varsRecv.nRecv.isPacketAllowed(counter.RAW_native()) else {
						logger.warning("sliding window rejected packet", metadata:["public-key_remote":"\(identifiedPublicKey)", "nRecv":"\(varsRecv.nRecv)", "tRecv":"\(varsRecv.tRecv.debugDescription)", "counter":"\(counter.RAW_native())"])
						return
					}

					// decrypt the payload into the encode buffer
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

					livePeerInfo.nRecvUpdate(context:context, now:now, varsRecv.nRecv, geometry:existingGeometryPositioned, mStaticPrivateKey:privateKey)
					context.fireChannelRead(wrapInboundOut(PeerPayload(publicKey: identifiedPublicKey, buffer: encodeBuffer)))
			}
		} catch let error {
			logger.error("error processing packet: \(error)")
			context.fireErrorCaught(error)
		}
	}
	
	internal func channelWritabilityChanged(context: ChannelHandlerContext) {
		defer {
			context.fireChannelWritabilityChanged()
		}
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.trace("channel writability changed.")
		context.eventLoop.execute { [weak self, c = ContextContainer(context:context)] in
			guard let self else { return }
			c.accessContext { contextPtr in
				outboundOutDriver.writabilityChanged(context:contextPtr.pointee, handler:self)
			}
		}
	}
}

// swift nio write handler function
extension WireguardHandler {
	/// applies an immediate encryption and writing of the given payload to the given public key.
	internal func writeBytes(context:ChannelHandlerContext, publicKey:PublicKey, payload:inout ByteBuffer, promise:EventLoopPromise<Void>?) -> WriteOrHold<OutboundOut>.Result? {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		let now = NIODeadline.now()
		logger[metadataKey: "public-key_remote"] = "\(publicKey)"
		guard let peerInfoLive = peerDeltaEngine.peerLookup(publicKey:publicKey) else {
			logger.error("peer is not configured. can not write data.")
			promise?.fail(PeerInfo.Live.UnknownPeerEndpoint())
			return nil
		}
		guard let ep = peerInfoLive.endpoint() else {
			logger.error("trying to write data to a peer with no known endpoint.")
			promise?.fail(PeerInfo.Live.UnknownPeerEndpoint())
			return nil
		}
		switch peerInfoLive.getSendStrategy(context:context, now:now, initiationValues:(mStaticPrivateKey:privateKey, endpointOverride:ep)) {
			case .queueForInitiatingHandshake:
				fallthrough
			case .queueWhileAwaitingKeyRotation:
				peerInfoLive.queuePostHandshake(context:context, data:payload, promise:promise)
				return nil
			case .sendImmediately(var sendValues):
				do {
					var forgedLength = 0
					forgedLength += MemoryLayout<Message.Data.Header>.size
					forgedLength += MemoryLayout<Tag>.size
					forgedLength += Message.Data.Payload.paddedLength(count:payload.readableBytes)
					encodeBuffer.clear(minimumCapacity:forgedLength)
					try encodeBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes:forgedLength) { bufferPtr in
						return try Message.Data.Payload.forge(receiverIndex:sendValues.session.geometry.mp, nonce:&sendValues.nSend, transportKey:sendValues.tSend, plainText:&payload, output:bufferPtr.baseAddress!)
					}
				} catch let error {
					logger.error("error thrown while trying to write outbound data", metadata:["error":"\(error)"])
					context.fireErrorCaught(error)
					promise?.fail(error)
					return nil
				}
				peerInfoLive.updateSendValues(context:context, now:now, sendValues, initiationValues:(mStaticPrivateKey:privateKey, endpointOverride:ep))
				let asAddressedEnvelope = AddressedEnvelope<ByteBuffer>(remoteAddress: SocketAddress(ep), data:encodeBuffer)
				logger.trace("writing data to peer.", metadata:["size":"\(payload.readableBytes) bytes", "public-key_remote":"\(publicKey)"])
				return outboundOutDriver.holdOrWrite(context:context, handler:self, asAddressedEnvelope, writePromise:promise)
		}
	}
	
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let peerPayload = unwrapOutboundIn(data)
		var (publicKey, payload) = (peerPayload.publicKey, peerPayload.associatedValue)
		_ = writeBytes(context:context, publicKey:publicKey, payload:&payload, promise:promise)
	}
}
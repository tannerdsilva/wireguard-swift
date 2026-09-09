import NIO
import Logging
import RAW
import RAW_dh25519
import RAW_chachapoly
import wireguard_crypto_core

internal final class PacketHandler:ChannelDuplexHandler, @unchecked Sendable {
	
	/// errors that may be fired by the PacketHandler
	internal enum Error:Swift.Error {
		/// specifies that the packet length does not match the expected length for the giveC, @unchecked Sendabn packet type
		/// - parameter type: the type of packet that was expected
		/// - parameter length: the length of the packet that was received
		case invalidPacketLengthForType(type:UInt8, length:Int)
		/// thrown when a packet type is received on the listening socket but that packet type is not recognized.
		/// - parameter type: the type of packet that was not recognized
		case packetTypeUnrecognized(type:UInt8)
	}
	
	/// the type of data that this handler will receive from upstream in the inbound pipeline. this is a datagram packet with an associated remote address.
	internal typealias InboundIn = AddressedEnvelope<ByteBuffer>
	private var packetsReadSinceLastReadComplete:Int = 0
	private var bytesReadSinceLastReadComplete:Int = 0
	/// the type of object that this handler will pass to the next handler in the pipeline. this is a tuple containing the endpoint of the sender and the parsed message.
	internal typealias InboundOut = (Endpoint, Message.NIO)

	
	internal typealias OutboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>
	private var packetsWrittenSinceLastFlush:Int = 0
	private var bytesWrittenSinceLastFlush:Int = 0

	/// logger instance for this handler
	private let log:Logger
	/// the mtu limits for this handler
	private let mtu:MTULimits
	/// counts the number of read operations that have been passed through this handler. used to ensure readComplete operations are only passed downstream when there have been reads.
	internal init(privateKey:MemoryGuarded<PrivateKey>, mtu:inout MTULimits, logLevel:consuming Logger.Level) {
		#if DEBUG
		guard mtu.mtuInboundIn == mtu.mtuInboundOut else {
			fatalError("fatal usage error - the inbound in/out values must be equal - \(String(describing:Self.self)) - \(#file):\(#line)")
		}
		guard mtu.mtuOutboundOut == mtu.mtuOutboundIn else {
			fatalError("fatal usage error - the outbound in/out values must be equal - \(String(describing:Self.self)) - \(#file):\(#line)")
		}
		#endif
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:privateKey))"
		buildLogger.logLevel = logLevel
		log = buildLogger
		self.mtu = mtu
	}
}

// MARK: Events
extension PacketHandler {
	internal func channelInactive(context: ChannelHandlerContext) {
		log.debug("Channel is inactive")
	}
	internal func handlerAdded(context:borrowing ChannelHandlerContext) {
		log.debug("handler added to pipeline.", metadata:["mtu_inboundIn":"\(mtu.mtuInboundIn)", "mtu_inboundOut":"\(mtu.mtuInboundOut)", "mtu_outboundOut":"\(mtu.mtuOutboundOut)", "mtu_outboundIn":"\(mtu.mtuOutboundIn)"])
	}
	
	internal func handlerRemoved(context:borrowing ChannelHandlerContext) {
		log.debug("handler removed from pipeline.")
	}

	internal func userInboundEventTriggered(context:borrowing ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}

// MARK: Read
extension PacketHandler {
	internal func channelReadComplete(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		guard packetsReadSinceLastReadComplete > 0 else {
			log.trace("read complete, but no reads were performed since the last read complete signal.")
			return
		}
		log.trace("read complete.", metadata:["packets_read":"\(packetsReadSinceLastReadComplete)", "bytes_read":"\(bytesReadSinceLastReadComplete)"])
		packetsReadSinceLastReadComplete = 0
		bytesReadSinceLastReadComplete = 0
		context.fireChannelReadComplete()
	}

	internal func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var logger = log
		var envelope = unwrapInboundIn(data)
		packetsReadSinceLastReadComplete += 1
		bytesReadSinceLastReadComplete += envelope.bytesOnWire
		let endpoint:Endpoint
		do {
			endpoint = try Endpoint(envelope.remoteAddress)
		} catch let error {
			#if DEBUG
			logger.error("failed to parse remote address.", metadata:["error":"\(error)"])
			#endif
			return
		}
		logger[metadataKey:"remote_address"] = "\(endpoint)"
		guard envelope.data.readableBytes > 0 else {
			#if DEBUG
			logger.trace("received udp packet of zero length. this packet will be ignored.")
			#endif
			return
		}
		let firstByte = envelope.data.withUnsafeReadableBytes { byteBuffer in
			return byteBuffer[0]
		}
		logger[metadataKey:"wg_packet_type"] = "\(firstByte)"
		guard envelope.data.readableBytes <= mtu.mtuInboundIn else {
			#if DEBUG
			logger.error("mtu for InboundIn is exceeding the configured limit.", metadata:["inbound_size":"\(envelope.data.readableBytes)", "mtu_inboundIn":"\(mtu.mtuInboundIn)"])
			#endif
			return
		}
		// proceed based on the first byte of the buffer
		let wireBytes:Int
		switch firstByte {
			case 0x1:
				wireBytes = MemoryLayout<Message.Initiation.Payload.Authenticated>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					guard byteBuffer.count == MemoryLayout<Message.Initiation.Payload.Authenticated>.size else {
						#if DEBUG
						logger.error("invalid handshake initiation packet.", metadata:["expected_length":"\(MemoryLayout<Message.Initiation.Payload.Authenticated>.size)", "actual_length":"\(byteBuffer.count)"])
						#endif
						return
					}
					#if DEBUG
					logger.trace("received handshake initiation packet.")
					#endif
					let packet = Message.Initiation.Payload.Authenticated(RAW_decode:byteBuffer)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.initiation(packet))))
				}
				break
			case 0x2:
				wireBytes = MemoryLayout<Message.Response.Payload.Authenticated>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					guard byteBuffer.count == MemoryLayout<Message.Response.Payload.Authenticated>.size else {
						#if DEBUG
						logger.error("invalid handshake response packet.", metadata:["expected_length": "\(MemoryLayout<Message.Response.Payload.Authenticated>.size)", "actual_length":"\(byteBuffer.count)"])
						#endif
						return
					}
					#if DEBUG
					logger.trace("received handshake response packet.")
					#endif
					let packet = Message.Response.Payload.Authenticated(RAW_decode:byteBuffer)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.response(packet))))
				}
				break
			case 0x3:
				wireBytes = MemoryLayout<Message.Cookie.Payload>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					#if DEBUG
					logger.trace("received cookie response packet.")
					#endif
					let packet = Message.Cookie.Payload(RAW_decode:byteBuffer)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.cookie(packet))))
				}
				break
			case 0x4:
				guard envelope.data.readableBytes >= (MemoryLayout<Message.Data.Header>.size + MemoryLayout<Tag>.size) else {
					#if DEBUG
					logger.error("datagram is too small.", metadata:["readable_bytes":"\(envelope.data.readableBytes)", "minimum_bytes":"\(MemoryLayout<Message.Data.Header>.size + MemoryLayout<Tag>.size)"])
					#endif
					return
				}
				_ = envelope.data.readInteger(as:UInt8.self)!
				guard envelope.data.readInteger(as:UInt8.self)! == 0, envelope.data.readInteger(as:UInt8.self)! == 0, envelope.data.readInteger(as:UInt8.self)! == 0 else {
					#if DEBUG
					logger.error("invalid packet format: reserved bytes not zeroed", metadata:["byte1":"\(envelope.data.readInteger(as:UInt8.self)!)", "byte2":"\(envelope.data.readInteger(as:UInt8.self)!)", "byte3":"\(envelope.data.readInteger(as:UInt8.self)!)"])
					#endif
					return
				}
				let peerIndexBytes = envelope.data.readBytes(length:MemoryLayout<PeerIndex>.size)!
				let peerIndex = peerIndexBytes.withUnsafeBytes { raw in
					return PeerIndex(RAW_decode:raw)!
				}
				let counterBytes = envelope.data.readBytes(length:MemoryLayout<Counter>.size)!
				let counterValue = counterBytes.withUnsafeBytes { raw in
					return Counter(RAW_decode:raw)!
				}
				wireBytes = envelope.data.readableBytes
				context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.data(recipientIndex:peerIndex, counter:counterValue, payload:envelope.data.readableBytesView))))
				break
			default:
				#if DEBUG
				logger.error("unrecognized packet type received: \(firstByte)")
				#endif
				return
		}
		packetsReadSinceLastReadComplete += 1
		bytesReadSinceLastReadComplete += wireBytes
	}
}

// MARK: Write
extension PacketHandler {
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let unwrappedData = unwrapOutboundIn(data)
		guard unwrappedData.data.readableBytes <= mtu.mtuOutboundOut else {
			#if DEBUG
			log.error("mtu for OutboundOut is exceeding the configured limit.", metadata:["outbound_size":"\(unwrappedData.data.readableBytes)", "mtu_outboundOut":"\(mtu.mtuOutboundOut)"])
			#endif
			promise?.fail(ChannelError.OutboundMessageMTUExceeded(attemptedOutboundSize:unwrappedData.data.readableBytes, mtuLimitOutbound:Int(mtu.mtuOutboundOut)))
			return
		}
		packetsWrittenSinceLastFlush += 1
		bytesWrittenSinceLastFlush += unwrappedData.bytesOnWire
		context.write(wrapOutboundOut(unwrappedData), promise:promise)
	}

	internal borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		defer {
			packetsWrittenSinceLastFlush = 0
			bytesWrittenSinceLastFlush = 0
		}
		guard packetsWrittenSinceLastFlush > 0 else {
			#if DEBUG
			log.trace("flush called, but no writes were performed since the last flush. not flushing.")
			#endif
			return
		}
		log.trace("flushing...", metadata:["packets_flushed":"\(packetsWrittenSinceLastFlush)", "bytes_flushed":"\(bytesWrittenSinceLastFlush)"])
		context.flush()
	}
}

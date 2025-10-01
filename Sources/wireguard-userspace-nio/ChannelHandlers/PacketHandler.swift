import NIO
import Logging
import RAW
import RAW_dh25519
import RAW_chachapoly
import wireguard_crypto_core

internal enum PacketTypeInbound {
	case encryptedTransit(PublicKey, PeerIndex, HandshakeGeometry<PeerIndex>, Message.Data.Payload)
	case keyExchange(PublicKey, PeerIndex, Result.Bytes32, Bool, HandshakeGeometry<PeerIndex>)
}

internal enum PacketTypeOutbound {
	case encryptedTransit(PublicKey, Message.Data.Payload)
	case handshakeInitiate(PublicKey, Endpoint?)
}

internal final class PacketHandler:ChannelDuplexHandler, @unchecked Sendable {
	/// errors that may be fired by the PacketHandler
	internal enum Error:Swift.Error {
		/// specifies that the packet length does not match the expected length for the given packet type
		/// - parameter type: the type of packet that was expected
		/// - parameter length: the length of the packet that was received
		case invalidPacketLengthForType(type:UInt8, length:Int)
		/// thrown when a packet type is received on the listening socket but that packet type is not recognized.
		/// - parameter type: the type of packet that was not recognized
		case packetTypeUnrecognized(type:UInt8)
		/// thrown when the packet mtu is too small to encompass the specified message
		case mtuExceeded
	}
	
	/// the type of data that this handler will receive from upstream in the inbound pipeline. this is a datagram packet with an associated remote address.
	internal typealias InboundIn = AddressedEnvelope<ByteBuffer>

	/// the type of object that this handler will pass to the next handler in the pipeline. this is a tuple containing the endpoint of the sender and the parsed message.
	internal typealias InboundOut = (Endpoint, Message.NIO)


	internal typealias OutboundIn = AddressedEnvelope<ByteBuffer>

	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private let log:Logger
	private let datagramMTU:UInt16

	/// counts the number of read operations that have been passed through this handler. used to ensure readComplete operations are only passed downstream when there have been reads.
	internal init(mtu:inout UInt16, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
		datagramMTU = mtu
	}

	internal func handlerAdded(context:ChannelHandlerContext) {
		log.debug("handler added to NIO pipeline.", metadata:["mtu":"\(datagramMTU)"])
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		log.debug("handler removed from NIO pipeline.")
	}

	internal func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
	
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		var logger = log
		var envelope = unwrapInboundIn(data)
		let endpoint:Endpoint
		do {
			endpoint = try Endpoint(envelope.remoteAddress)
		} catch let error {
			logger.error("failed to parse remote address: '\(envelope.remoteAddress.description)'", metadata:["error":"\(error)"])
			context.fireErrorCaught(error)
			return
		}
		logger[metadataKey:"remote_address"] = "\(endpoint)"
		let firstByte = envelope.data.withUnsafeReadableBytes { byteBuffer in
			return byteBuffer[0]
		}
		logger[metadataKey:"packet_type"] = "\(firstByte)"
		
		// proceed based on the first byte of the buffer
		let wireBytes:Int
		switch firstByte {
			case 0x1:
				wireBytes = MemoryLayout<Message.Initiation.Payload.Authenticated>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					guard byteBuffer.count == MemoryLayout<Message.Initiation.Payload.Authenticated>.size else {
						logger.error("invalid handshake initiation packet size: \(byteBuffer.count)", metadata:["expected_length":"\(MemoryLayout<Message.Initiation.Payload.Authenticated>.size)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x1, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake initiation packet. sending downstream in pipeline...")
					let packet = Message.Initiation.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Initiation.Payload.Authenticated>.size)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.initiation(packet))))
				}
			case 0x2:
				wireBytes = MemoryLayout<Message.Response.Payload.Authenticated>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					guard byteBuffer.count == MemoryLayout<Message.Response.Payload.Authenticated>.size else {
						logger.error("invalid handshake response packet size: \(byteBuffer.count)", metadata:["expected_length": "\(MemoryLayout<Message.Response.Payload.Authenticated>.size)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x2, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake response packet. sending downstream in pipeline...")
					let packet = Message.Response.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Response.Payload.Authenticated>.size)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.response(packet))))
				}
			case 0x3:
				wireBytes = MemoryLayout<Message.Cookie.Payload>.size
				envelope.data.withUnsafeReadableBytes { byteBuffer in
					logger.debug("received cookie response packet. sending downstream in pipeline...")
					let packet = Message.Cookie.Payload(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Cookie.Payload>.size)!
					context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.cookie(packet))))
				}
			case 0x4:
				guard envelope.data.readableBytes >= (MemoryLayout<Message.Data.Payload>.size + MemoryLayout<Tag>.size) else {
					logger.error("datagram mtu exceeded", metadata:["mtu":"\(datagramMTU)", "packet_size":"\(envelope.data.readableBytes)"])
					context.fireErrorCaught(Error.mtuExceeded)
					return
				}
				_ = envelope.data.readInteger(as:UInt8.self)!
				guard envelope.data.readInteger(as:UInt8.self)! == 0, envelope.data.readInteger(as:UInt8.self)! == 0, envelope.data.readInteger(as:UInt8.self)! == 0 else {
					logger.error("invalid packet format: reserved bytes not zeroed", metadata:["byte1":"\(envelope.data.readInteger(as:UInt8.self)!)", "byte2":"\(envelope.data.readInteger(as:UInt8.self)!)", "byte3":"\(envelope.data.readInteger(as:UInt8.self)!)"])
					return
				}
				let peerIndex = PeerIndex(RAW_staticbuff:envelope.data.readBytes(length:MemoryLayout<PeerIndex>.size)!)
				let counterValue = Counter(RAW_staticbuff:envelope.data.readBytes(length:MemoryLayout<Counter>.size)!)
				guard envelope.data.readableBytes >= MemoryLayout<Tag>.size else {
					logger.error("datagram mtu exceeded", metadata:["mtu":"\(datagramMTU)", "packet_size":"\(envelope.data.readableBytes)"])
					context.fireErrorCaught(Error.mtuExceeded)
					return
				}
				let availableBytes = envelope.data.readableBytes - MemoryLayout<Tag>.size
				wireBytes = availableBytes
				context.fireChannelRead(wrapInboundOut((endpoint, Message.NIO.data(recipientIndex:peerIndex, counter:counterValue, payload:envelope.data.readableBytesView))))

			default:
				logger.error("unrecognized packet type received: \(firstByte)")
				context.fireErrorCaught(Error.packetTypeUnrecognized(type:firstByte))
				return
		}
	}

	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let envelope = unwrapOutboundIn(data)
		context.write(wrapOutboundOut(envelope), promise:promise)
	}
}

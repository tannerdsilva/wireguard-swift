import NIO
import Logging
import RAW
import RAW_dh25519
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
	}
	
	internal typealias InboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias InboundOut = (Endpoint, Message)
	internal typealias OutboundIn = (Endpoint, Message)
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private let log:Logger

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}

	internal func handlerAdded(context:ChannelHandlerContext) {
		log.debug("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		log.debug("handler removed from NIO pipeline.")
	}

	
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		var logger = log
		let envelope = unwrapInboundIn(data)
		let endpoint:Endpoint
		do {
			endpoint = try Endpoint(envelope.remoteAddress)
		} catch let error {
			logger.error("failed to parse remote address: '\(envelope.remoteAddress.description)'", metadata:["error":"\(error)"])
			context.fireErrorCaught(error)
			return
		}
		logger[metadataKey:"remote_address"] = "\(endpoint)"
		envelope.data.withUnsafeReadableBytes { byteBuffer in
			let firstByte = byteBuffer[0]
			logger[metadataKey:"packet_type"] = "\(firstByte)"
			logger.trace("received packet...")
			// proceed based on the first byte of the buffer
			switch firstByte {
				case 0x1:
					guard byteBuffer.count == MemoryLayout<Message.Initiation.Payload.Authenticated>.size else {
						logger.error("invalid handshake initiation packet size: \(byteBuffer.count)", metadata:["expected_length":"\(MemoryLayout<Message.Initiation.Payload.Authenticated>.size)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x1, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake initiation packet. sending downstream in pipeline...")
					context.fireChannelRead(wrapInboundOut((endpoint, Message.initiation(Message.Initiation.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Initiation.Payload.Authenticated>.size)!))))
				case 0x2:
					guard byteBuffer.count == MemoryLayout<Message.Response.Payload.Authenticated>.size else {
						logger.error("invalid handshake response packet size: \(byteBuffer.count)", metadata:["expected_length": "\(MemoryLayout<Message.Response.Payload.Authenticated>.size)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x2, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake response packet. sending downstream in pipeline...")
					context.fireChannelRead(wrapInboundOut((endpoint, Message.response(Message.Response.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Response.Payload.Authenticated>.size)!))))
				case 0x3:
					logger.debug("received cookie response packet. sending downstream in pipeline...")
					context.fireChannelRead(wrapInboundOut((endpoint, Message.cookie(Message.Cookie.Payload(RAW_decode:byteBuffer.baseAddress!, count:MemoryLayout<Message.Cookie.Payload>.size)!))))
				case 0x4:
					logger.debug("received transit data packet of size \(byteBuffer.count), sending downstream in pipeline...")
					context.fireChannelRead(wrapInboundOut((endpoint, Message.data(Message.Data.Payload(RAW_decode:byteBuffer.baseAddress!, count:byteBuffer.count)!))))
				default:
					logger.error("unrecognized packet type received: \(byteBuffer[0])")
					context.fireErrorCaught(Error.packetTypeUnrecognized(type:byteBuffer[0]))
			}
		}
	}
	
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		// handles receiving Outbound Packets and sending out a UDP packet to the remote address
		let (destinationEndpoint, mode) = unwrapOutboundIn(data)
		var logger = log
		logger[metadataKey:"remote_address"] = "\(destinationEndpoint)"
		logger.trace("writing data...")
		let sendBuffer:ByteBuffer
		switch mode {
			case let .initiation(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<Message.Initiation.Payload.Authenticated>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				promise?.futureResult.whenComplete { [l = logger, de = destinationEndpoint] r in
					switch r {
					case .success:
						l.debug("handshake initiation packet sent successfully")
					case .failure(let error):
						l.error("failed to send initiation packet: \(error)")
					}
				}
			case let .response(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<Message.Response.Payload.Authenticated>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				promise?.futureResult.whenComplete { [l = logger, de = destinationEndpoint] r in
					switch r {
					case .success:
						l.debug("handshake response packet sent successfully")
					case .failure(let error):
						l.error("failed to send response packet: \(error)")
					}
				}
			case let .cookie(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<Message.Cookie.Payload>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				promise?.futureResult.whenComplete { [l = logger, de = destinationEndpoint] r in
					switch r {
					case .success:
						l.debug("cookie packet sent successfully")
					case .failure(let error):
						l.error("failed to send cookie packet: \(error)")
					}
				}
			case .data(let payload):
				var size: RAW.size_t = 0
				payload.RAW_encode(count: &size)
				var buffer = context.channel.allocator.buffer(capacity:size)
				buffer.writeWithUnsafeMutableBytes(minimumWritableBytes:size) { [p = payload] ob in
					return ob.baseAddress!.distance(to:p.RAW_encode(dest:ob.baseAddress!.assumingMemoryBound(to:UInt8.self)))
				}
                sendBuffer = buffer
				promise?.futureResult.whenComplete { [l = logger, de = destinationEndpoint, s = size] r in
					switch r {
					case .success:
						l.debug("data packet sent successfully", metadata:["packet_length":"\(s)"])
					case .failure(let error):
						l.error("failed to send data packet: \(error)")
					}
				}
		}
		context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress:SocketAddress(destinationEndpoint), data:sendBuffer)), promise:promise)
	}
}

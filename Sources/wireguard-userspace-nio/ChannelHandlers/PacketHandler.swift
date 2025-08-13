import NIO
import Logging
import RAW
import RAW_dh25519
import wireguard_crypto_core

internal enum PacketType {
	/// represents an inbound transit packet, which is used to carry data between peers after the handshake is complete
    case encryptedTransit(Endpoint, Message.Data.Payload)
    /// represents key creation information for post handshake validation
    case keyExchange(PublicKey, Endpoint, PeerIndex, Result.Bytes32, Bool)
    /// represents a handshake invoker
    case initiationInvoker(PublicKey, Endpoint)
}


internal final class PacketHandler:ChannelDuplexHandler, Sendable {
	/// errors that may be fired by the PacketHandler
	internal enum Error:Swift.Error {
		/// specifies that the packet length does not match the expected length for the given packet type
		/// - parameter type: the type of packet that was expected
		/// - parameter length: the length of the packet that was received
		case invalidPacketLengthForType(type:UInt8, length:Int)
	}
	
	internal typealias InboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias InboundOut = (Endpoint, Message)
	
	internal typealias OutboundIn = (SocketAddress, Message)
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private let logger:Logger

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let envelope = unwrapInboundIn(data)
		let endpoint:Endpoint
		do {
			endpoint = try Endpoint(envelope.remoteAddress)
		} catch let error {
			logger.error("failed to parse remote address: \(envelope.remoteAddress.description)", metadata:["error":"\(error)"])
			context.fireErrorCaught(error)
			return
		}
		envelope.data.withUnsafeReadableBytes { byteBuffer in
			// proceed based on the first byte of the buffer
			switch byteBuffer[0] {
				case 0x1:
					guard byteBuffer.count == MemoryLayout<Message.Initiation.Payload.Authenticated>.size else {
						logger.error("invalid handshake initiation packet size: \(byteBuffer.count)", metadata:["expected_length":"\(MemoryLayout<Message.Initiation.Payload.Authenticated>.size)", "remote_address":"\(envelope.remoteAddress.description)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x1, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake initiation packet. sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
					context.fireChannelRead(wrapInboundOut((endpoint, Message.initiation(Message.Initiation.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count: MemoryLayout<Message.Initiation.Payload.Authenticated>.size)!))))
				case 0x2:
					guard byteBuffer.count == MemoryLayout<Message.Response.Payload.Authenticated>.size else {
						logger.error("invalid handshake response packet size: \(byteBuffer.count)", metadata:["expected_length": "\(MemoryLayout<Message.Response.Payload.Authenticated>.size)", "remote_address":"\(envelope.remoteAddress.description)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x2, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake response packet. sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
					context.fireChannelRead(wrapInboundOut((endpoint, Message.response(Message.Response.Payload.Authenticated(RAW_decode:byteBuffer.baseAddress!, count: MemoryLayout<Message.Response.Payload.Authenticated>.size)!))))
				case 0x3:
					logger.debug("received cookie response packet. sending downstream in pipeline")
					context.fireChannelRead(wrapInboundOut((endpoint, Message.cookie(Message.Cookie.Payload(RAW_decode:byteBuffer.baseAddress!, count: MemoryLayout<Message.Cookie.Payload>.size)!))))
				case 0x4:
					logger.debug("received transit data packet of size \(byteBuffer.count), sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
                    context.fireChannelRead(wrapInboundOut((endpoint, Message.data(Message.Data.Payload(RAW_decode:byteBuffer.baseAddress!, count: byteBuffer.count)!))))
				default:
                    logger.debug("Invalid Packet type \(byteBuffer[0])")
			}
		}
	}
	
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		// handles receiving Outbound Packets and sending out a UDP packet to the remote address
		let destinationEndpoint:SocketAddress
		let mode:Message
		(destinationEndpoint, mode) = unwrapOutboundIn(data)
		let sendBuffer: ByteBuffer
		switch mode {
			case let .initiation(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<Message.Initiation.Payload.Authenticated>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				logger.debug("sending handshake initiation packet of size \(sendBuffer.readableBytes)", metadata:["remote_address":"\(destinationEndpoint.description)"])
			case let .response(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<Message.Response.Payload.Authenticated>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				logger.debug("sending handshake response packet of size \(sendBuffer.readableBytes)", metadata:["remote_address":"\(destinationEndpoint.description)"])
			case let .cookie(payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<CookieReplyMessage.Payload>.size)
				buffer.writeBytes(payload)
				sendBuffer = buffer
				logger.debug("sending cookie packet of size \(sendBuffer.readableBytes)", metadata:["remote_address":"\(destinationEndpoint.description)"])
            case .data(let payload):
                logger.trace("sending transit packet outbound")
                var size: RAW.size_t = 0
                payload.RAW_encode(count: &size)
                var buffer = context.channel.allocator.buffer(capacity:size)
                buffer.writeWithUnsafeMutableBytes(minimumWritableBytes:size) { [p = payload] ob in
					return ob.baseAddress!.distance(to:p.RAW_encode(dest:ob.baseAddress!.assumingMemoryBound(to:UInt8.self)))
				}
                sendBuffer = buffer
		}
		context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress:destinationEndpoint, data:sendBuffer)), promise:promise)
	}
}

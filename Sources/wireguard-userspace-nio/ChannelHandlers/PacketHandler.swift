import NIO
import Logging

internal enum PacketType {
	/// represents a handshake initiation packet, sent by the initiator to start the handshake
	case handshakeInitiation(SocketAddress, HandshakeInitiationMessage.AuthenticatedPayload)
	/// represents a handshake response packet, sent by the responder to complete the handshake sent by the initiator
	case handshakeResponse(SocketAddress, HandshakeResponseMessage.AuthenticatedPayload)
	/// represents a cookie packet.
	case cookie
	/// represents a transit packet, which is used to carry data between peers after the handshake is complete
    case transit(SocketAddress, DataMessage.DataPayload)
    /// represents key creation information for post handshake validation
    case keyExchange(PeerIndex, Result32)
    /// represents a handshake invoker
    case initiationInvoker(SocketAddress)
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
	internal typealias InboundOut = PacketType
	
	internal typealias OutboundIn = PacketType
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private let logger:Logger

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let envelope = unwrapInboundIn(data)
		envelope.data.withUnsafeReadableBytes { byteBuffer in
			// proceed based on the first byte of the buffer
			switch byteBuffer[0] {
				case 0x1:
					guard byteBuffer.count == MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size else {
						logger.error("invalid handshake initiation packet size: \(byteBuffer.count)", metadata:["expected_length":"\(MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size)", "remote_address":"\(envelope.remoteAddress.description)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x1, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake initiation packet. sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
					context.fireChannelRead(wrapInboundOut(PacketType.handshakeInitiation(envelope.remoteAddress, HandshakeInitiationMessage.AuthenticatedPayload(RAW_decode:byteBuffer.baseAddress!, count: MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size)!)))
				case 0x2:
					guard byteBuffer.count == MemoryLayout<HandshakeResponseMessage.AuthenticatedPayload>.size else {
						logger.error("invalid handshake response packet size: \(byteBuffer.count)", metadata:["expected_length": "\(MemoryLayout<HandshakeResponseMessage.AuthenticatedPayload>.size)", "remote_address":"\(envelope.remoteAddress.description)"])
						context.fireErrorCaught(Error.invalidPacketLengthForType(type:0x2, length:byteBuffer.count))
						return
					}
					logger.debug("received handshake response packet. sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
					context.fireChannelRead(wrapInboundOut(PacketType.handshakeResponse(envelope.remoteAddress, HandshakeResponseMessage.AuthenticatedPayload(RAW_decode:byteBuffer.baseAddress!, count: MemoryLayout<HandshakeResponseMessage.AuthenticatedPayload>.size)!)))
				case 0x3:
					fallthrough
				case 0x4:
					logger.debug("received transit data packet of size \(byteBuffer.count), sending downstream in pipeline...", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
                    context.fireChannelRead(wrapInboundOut(PacketType.transit(envelope.remoteAddress, DataMessage.DataPayload(RAW_decode:byteBuffer.baseAddress!, count: byteBuffer.count)!)))
				default:
					logger.warning("received packet with unknown type: \(byteBuffer[0])", metadata:["remote_address":"\(envelope.remoteAddress.description)"])
			}
		}
	}
	
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		// handles receiving Outbound Packets and sending out a UDP packet to the remote address
		let destinationEndpoint:SocketAddress
		let sendBuffer: ByteBuffer
		switch unwrapOutboundIn(data) {
			case let .handshakeInitiation(endpoint, payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size)
				buffer.writeBytes(payload)
				destinationEndpoint = endpoint
				sendBuffer = buffer
				logger.debug("sending handshake initiation packet of size \(sendBuffer.readableBytes)", metadata:["remote_address":"\(destinationEndpoint.description)"])
			case let .handshakeResponse(endpoint, payload):
				var buffer = context.channel.allocator.buffer(capacity:MemoryLayout<HandshakeResponseMessage.AuthenticatedPayload>.size)
				buffer.writeBytes(payload)
				destinationEndpoint = endpoint
				sendBuffer = buffer
				logger.debug("sending handshake response packet of size \(sendBuffer.readableBytes)", metadata:["remote_address":"\(destinationEndpoint.description)"])
			case .cookie:
				logger.warning("attempted to send cookie packet, which is not supported")
				return
			case .transit:
				logger.warning("attempted to send transit packet, which is not supported")
				return
            case .keyExchange:
                logger.warning("attempted to send transit packet, which is not supported")
                return
            case .initiationInvoker:
                logger.warning("attempted to send transit packet, which is not supported")
                return
		}
		context.writeAndFlush(wrapOutboundOut(AddressedEnvelope(remoteAddress:destinationEndpoint, data:sendBuffer)), promise:promise)
	}
}

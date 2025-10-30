import NIO
import Logging
import RAW
import RAW_dh25519
import RAW_chachapoly
import wireguard_crypto_core

internal final class EncryptedHandler:ChannelDuplexHandler, @unchecked Sendable {
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
	typealias InboundIn = (Endpoint, Message.NIO)
	typealias InboundOut = (Endpoint, Message.NIO)
	
	internal typealias OutboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private var eph:EncryptedPacketHandler
	/// logger instance for this handler
	private let log:Logger

	internal init(eph: some EncryptedPacketHandler, logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
		self.eph = eph
	}
}

// MARK: Events
extension EncryptedHandler {
	internal func handlerAdded(context:borrowing ChannelHandlerContext) {
		log.debug("handler added to pipeline.")
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
extension EncryptedHandler {
	internal func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapInboundIn(data)
		eph.willReadInbound(&unwrappedData.1)
		context.fireChannelRead(wrapInboundOut(unwrappedData))
	}
}

// MARK: Write
extension EncryptedHandler {
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapOutboundIn(data)
		eph.willWriteOutbound(&unwrappedData.data)
		context.write(wrapOutboundOut(unwrappedData), promise:promise)
	}

	internal borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.trace("flushing...")
		context.flush()
	}
}

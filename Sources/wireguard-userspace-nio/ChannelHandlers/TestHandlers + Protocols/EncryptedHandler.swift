import NIO
import Logging
import RAW
import wireguard_crypto_core

internal final class EncryptedPacketHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (Endpoint, Message.NIO)
	internal typealias InboundOut = (Endpoint, Message.NIO)
	
	internal typealias OutboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private var epp:EncryptedPacketProcessor
	/// logger instance for this handler
	private let log:Logger

	internal init(epp: some EncryptedPacketProcessor, logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
		self.epp = epp
	}
}

// MARK: Events
extension EncryptedPacketHandler {
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
extension EncryptedPacketHandler {
	internal func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapInboundIn(data)
		epp.willReadInbound(&unwrappedData.1)
		context.fireChannelRead(wrapInboundOut(unwrappedData))
	}
}

// MARK: Write
extension EncryptedPacketHandler {
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapOutboundIn(data)
		var endpoint = try! Endpoint(unwrappedData.remoteAddress)
		epp.willWriteOutbound(&unwrappedData.data, ep:&endpoint)
		unwrappedData.remoteAddress = SocketAddress(endpoint)
		context.write(wrapOutboundOut(unwrappedData), promise:promise)
	}

	internal borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.flush()
	}
}

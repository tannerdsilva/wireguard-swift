import NIO
import Logging
import RAW
import wireguard_crypto_core

internal final class KCPTestingHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PeerAssociated<KCPSegment>
	internal typealias InboundOut = PeerAssociated<KCPSegment>
	
	internal typealias OutboundIn = PeerAssociated<KCPSegment>
	internal typealias OutboundOut = PeerAssociated<KCPSegment>

	private var eph:EncryptedPacketProcessor
	/// logger instance for this handler
	private let log:Logger

	internal init(eph: some EncryptedPacketProcessor, logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
		self.eph = eph
	}
}

// MARK: Events
extension KCPTestingHandler {
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
extension KCPTestingHandler {
	internal func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapInboundIn(data)
//		eph.willReadInbound(&unwrappedData.1)
		context.fireChannelRead(wrapInboundOut(unwrappedData))
	}
}

// MARK: Write
extension KCPTestingHandler {
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var unwrappedData = unwrapOutboundIn(data)
//		eph.willWriteOutbound(&unwrappedData.data)
		context.write(wrapOutboundOut(unwrappedData), promise:promise)
	}

	internal borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.flush()
	}
}
